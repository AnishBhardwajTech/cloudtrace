package com.cloudtrace.analysis;

import com.cloudtrace.model.Evidence;
import com.cloudtrace.model.Finding;
import com.cloudtrace.model.Severity;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** The built-in detection rules. */
public final class Rules {
    private Rules() {}

    public static List<DetectionRule> all() {
        return List.of(new RootAccountUsage(), new ConsoleLoginWithoutMfa(), new BruteForceLogin(),
                new LoggingTampering(), new PrivilegeEscalation(), new SecurityGroupOpenedToWorld(),
                new S3ExposureChange(), new AccessDeniedBurst());
    }

    static final class RootAccountUsage extends EventMatchRule {
        public String id() { return "ROOT-USAGE"; }
        public String title() { return "Root account used"; }
        public Severity severity() { return Severity.HIGH; }
        protected boolean matches(Evidence e) { return "root".equals(e.getActor()) && !e.isFailure(); }
    }

    static final class ConsoleLoginWithoutMfa extends EventMatchRule {
        public String id() { return "LOGIN-NO-MFA"; }
        public String title() { return "Console login without MFA"; }
        public Severity severity() { return Severity.MEDIUM; }
        protected boolean matches(Evidence e) {
            if (!"ConsoleLogin".equals(e.getEventName())) return false;
            var j = Json.parse(e.getRawJson());
            return "Success".equals(Json.at(j, "responseElements.ConsoleLogin"))
                    && "No".equalsIgnoreCase(Json.at(j, "additionalEventData.MFAUsed"));
        }
    }

    static final class LoggingTampering extends EventMatchRule {
        static final Set<String> EVENTS = Set.of("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
                "DeleteFlowLogs", "DeleteDetector", "DisableSecurityHub", "DeleteConfigurationRecorder",
                "StopConfigurationRecorder");
        public String id() { return "LOG-TAMPER"; }
        public String title() { return "Audit logging disabled or modified"; }
        public Severity severity() { return Severity.CRITICAL; }
        protected boolean matches(Evidence e) { return EVENTS.contains(e.getEventName()) && !e.isFailure(); }
    }

    static final class PrivilegeEscalation extends EventMatchRule {
        static final Set<String> EVENTS = Set.of("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
                "PutUserPolicy", "PutRolePolicy", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile",
                "UpdateAssumeRolePolicy", "AddUserToGroup", "CreatePolicyVersion");
        public String id() { return "PRIV-ESC"; }
        public String title() { return "Possible privilege escalation"; }
        public Severity severity() { return Severity.HIGH; }
        protected boolean matches(Evidence e) {
            if (!EVENTS.contains(e.getEventName()) || e.isFailure()) return false;
            var j = Json.parse(e.getRawJson());
            String target = Json.at(j, "requestParameters.userName");
            String policy = Json.at(j, "requestParameters.policyArn");
            boolean grantsAdmin = policy.endsWith("/AdministratorAccess") || policy.endsWith("/IAMFullAccess");
            boolean actsOnOther = !target.isEmpty() && !target.equals(e.getActor());
            boolean inline = e.getEventName().startsWith("Put") || e.getEventName().equals("CreatePolicyVersion")
                    || e.getEventName().equals("UpdateAssumeRolePolicy");
            return grantsAdmin || actsOnOther || inline;
        }
    }

    static final class SecurityGroupOpenedToWorld extends EventMatchRule {
        public String id() { return "SG-OPENED"; }
        public String title() { return "Security group opened to the internet"; }
        public Severity severity() { return Severity.HIGH; }
        protected boolean matches(Evidence e) {
            return "AuthorizeSecurityGroupIngress".equals(e.getEventName()) && !e.isFailure()
                    && (e.getRawJson().contains("\"0.0.0.0/0\"") || e.getRawJson().contains("\"::/0\""));
        }
    }

    static final class S3ExposureChange extends EventMatchRule {
        static final Set<String> EVENTS = Set.of("PutBucketAcl", "PutBucketPolicy", "DeleteBucketPolicy",
                "DeleteBucketPublicAccessBlock", "PutBucketPublicAccessBlock", "DeleteBucketEncryption");
        public String id() { return "S3-EXPOSURE"; }
        public String title() { return "S3 bucket access controls changed"; }
        public Severity severity() { return Severity.MEDIUM; }
        protected boolean matches(Evidence e) { return EVENTS.contains(e.getEventName()) && !e.isFailure(); }
    }

    /** Sliding-window rule: N events by the same key within a time window. */
    abstract static class BurstRule implements DetectionRule {
        abstract boolean candidate(Evidence e);
        abstract String key(Evidence e);
        abstract int threshold();
        abstract Duration window();

        List<Evidence> extra(List<Evidence> timeline, String key, List<Evidence> burst) { return List.of(); }

        String describe(String key, List<Evidence> burst, List<Evidence> extra) {
            return burst.size() + " events from " + key + " within " + window().toMinutes() + " minutes";
        }

        Severity severityFor(List<Evidence> extra) { return severity(); }

        @Override
        public List<Finding> evaluate(List<Evidence> timeline) {
            Map<String, Deque<Evidence>> windows = new LinkedHashMap<>();
            Map<String, List<Evidence>> fired = new LinkedHashMap<>();
            for (Evidence e : timeline) {
                if (!candidate(e)) continue;
                String k = key(e);
                Deque<Evidence> w = windows.computeIfAbsent(k, x -> new ArrayDeque<>());
                w.addLast(e);
                while (Duration.between(w.peekFirst().getEventTime(), e.getEventTime()).compareTo(window()) > 0) w.pollFirst();
                if (w.size() >= threshold()) {
                    List<Evidence> burst = fired.computeIfAbsent(k, x -> new ArrayList<>());
                    for (Evidence x : w) if (!burst.contains(x)) burst.add(x);
                }
            }
            List<Finding> out = new ArrayList<>();
            fired.forEach((k, burst) -> {
                List<Evidence> extra = extra(timeline, k, burst);
                List<Evidence> all = new ArrayList<>(burst);
                all.addAll(extra);
                out.add(new Finding(null, null, id(), title(), severityFor(extra), burst.get(0).getActor(),
                        burst.get(0).getEventTime(), all.get(all.size() - 1).getEventTime(),
                        describe(k, burst, extra), all.stream().map(Evidence::getEventId).toList()));
            });
            return out;
        }
    }

    static final class BruteForceLogin extends BurstRule {
        public String id() { return "BRUTE-FORCE"; }
        public String title() { return "Repeated failed console logins"; }
        public Severity severity() { return Severity.HIGH; }
        int threshold() { return 5; }
        Duration window() { return Duration.ofMinutes(10); }
        String key(Evidence e) { return e.getSourceIp(); }
        boolean candidate(Evidence e) {
            return "ConsoleLogin".equals(e.getEventName()) && e.getSourceIp() != null
                    && "Failure".equals(Json.at(Json.parse(e.getRawJson()), "responseElements.ConsoleLogin"));
        }

        /** A successful login from the same IP after the failures means the attack likely worked. */
        @Override
        List<Evidence> extra(List<Evidence> timeline, String ip, List<Evidence> burst) {
            var last = burst.get(burst.size() - 1).getEventTime();
            return timeline.stream().filter(e -> "ConsoleLogin".equals(e.getEventName()) && ip.equals(e.getSourceIp())
                    && e.getEventTime().isAfter(last)
                    && "Success".equals(Json.at(Json.parse(e.getRawJson()), "responseElements.ConsoleLogin")))
                    .limit(1).toList();
        }

        @Override
        Severity severityFor(List<Evidence> extra) { return extra.isEmpty() ? Severity.HIGH : Severity.CRITICAL; }

        @Override
        String describe(String ip, List<Evidence> burst, List<Evidence> extra) {
            String base = burst.size() + " failed console logins from " + ip + " within 10 minutes";
            return extra.isEmpty() ? base : base + ", followed by a SUCCESSFUL login as " + extra.get(0).getActor();
        }
    }

    static final class AccessDeniedBurst extends BurstRule {
        public String id() { return "RECON"; }
        public String title() { return "Burst of access-denied errors (reconnaissance)"; }
        public Severity severity() { return Severity.MEDIUM; }
        int threshold() { return 10; }
        Duration window() { return Duration.ofMinutes(15); }
        String key(Evidence e) { return e.getActor(); }
        @Override
        String describe(String actor, List<Evidence> burst, List<Evidence> extra) {
            return burst.size() + " access-denied errors by " + actor + " within 15 minutes across "
                    + burst.stream().map(Evidence::getEventName).distinct().count() + " different API calls";
        }

        boolean candidate(Evidence e) {
            String c = e.getErrorCode() == null ? "" : e.getErrorCode();
            return c.contains("AccessDenied") || c.contains("UnauthorizedOperation") || c.contains("Unauthorized");
        }
    }
}
