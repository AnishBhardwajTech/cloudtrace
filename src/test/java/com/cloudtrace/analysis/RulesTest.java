package com.cloudtrace.analysis;

import com.cloudtrace.TestData;
import com.cloudtrace.model.Evidence;
import com.cloudtrace.model.Finding;
import com.cloudtrace.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.cloudtrace.TestData.at;
import static com.cloudtrace.TestData.event;
import static org.junit.jupiter.api.Assertions.*;

class RulesTest {

    private static List<Finding> run(DetectionRule rule, Evidence... events) {
        return new Analyzer(List.of(rule)).analyze(List.of(events));
    }

    private static Evidence failedLogin(int min, int sec, String ip) {
        return event("victim", "ConsoleLogin", at(min, sec),
                "\"sourceIPAddress\":\"" + ip + "\",\"errorCode\":\"Failed authentication\",\"responseElements\":{\"ConsoleLogin\":\"Failure\"}");
    }

    @Test
    void rootUsage() {
        var f = run(new Rules.RootAccountUsage(), event("root", "ListBuckets", at(0, 0), ""), event("alice", "ListBuckets", at(1, 0), ""));
        assertEquals(1, f.size());
        assertEquals("root", f.get(0).actor());
    }

    @Test
    void consoleLoginWithoutMfa() {
        var noMfa = event("bob", "ConsoleLogin", at(0, 0), "\"responseElements\":{\"ConsoleLogin\":\"Success\"},\"additionalEventData\":{\"MFAUsed\":\"No\"}");
        var mfa = event("amy", "ConsoleLogin", at(1, 0), "\"responseElements\":{\"ConsoleLogin\":\"Success\"},\"additionalEventData\":{\"MFAUsed\":\"Yes\"}");
        var f = run(new Rules.ConsoleLoginWithoutMfa(), noMfa, mfa);
        assertEquals(List.of("bob"), f.stream().map(Finding::actor).toList());
    }

    @Test
    void bruteForceNeedsFiveFailuresInTenMinutes() {
        var spread = run(new Rules.BruteForceLogin(), failedLogin(0, 0, "9.9.9.9"), failedLogin(4, 0, "9.9.9.9"),
                failedLogin(8, 0, "9.9.9.9"), failedLogin(12, 0, "9.9.9.9"), failedLogin(16, 0, "9.9.9.9"));
        assertTrue(spread.isEmpty(), "5 failures over 16 minutes is below the threshold");

        List<Evidence> burst = new ArrayList<>();
        for (int i = 0; i < 6; i++) burst.add(failedLogin(0, i * 30, "9.9.9.9"));
        var f = run(new Rules.BruteForceLogin(), burst.toArray(Evidence[]::new));
        assertEquals(1, f.size());
        assertEquals(Severity.HIGH, f.get(0).severity());
        assertEquals(6, f.get(0).evidenceEventIds().size());
    }

    @Test
    void bruteForceFollowedBySuccessIsCritical() {
        List<Evidence> ev = new ArrayList<>();
        for (int i = 0; i < 5; i++) ev.add(failedLogin(0, i * 30, "9.9.9.9"));
        ev.add(event("victim", "ConsoleLogin", at(5, 0), "\"sourceIPAddress\":\"9.9.9.9\",\"responseElements\":{\"ConsoleLogin\":\"Success\"}"));
        var f = run(new Rules.BruteForceLogin(), ev.toArray(Evidence[]::new));
        assertEquals(Severity.CRITICAL, f.get(0).severity());
        assertTrue(f.get(0).description().contains("SUCCESSFUL"));
    }

    @Test
    void loggingTampering() {
        var f = run(new Rules.LoggingTampering(), event("x", "StopLogging", at(0, 0), ""),
                event("x", "DeleteTrail", at(1, 0), "\"errorCode\":\"AccessDenied\""));
        assertEquals(1, f.size());
        assertEquals(1, f.get(0).evidenceEventIds().size(), "failed attempts are not counted as tampering");
        assertEquals(Severity.CRITICAL, f.get(0).severity());
    }

    @Test
    void privilegeEscalation() {
        var adminSelf = event("eve", "AttachUserPolicy", at(0, 0),
                "\"requestParameters\":{\"userName\":\"eve\",\"policyArn\":\"arn:aws:iam::aws:policy/AdministratorAccess\"}");
        var keyForOther = event("eve", "CreateAccessKey", at(1, 0), "\"requestParameters\":{\"userName\":\"admin\"}");
        var ownKey = event("sam", "CreateAccessKey", at(2, 0), "\"requestParameters\":{\"userName\":\"sam\"}");
        var f = run(new Rules.PrivilegeEscalation(), adminSelf, keyForOther, ownKey);
        assertEquals(1, f.size());
        assertEquals("eve", f.get(0).actor());
        assertEquals(2, f.get(0).evidenceEventIds().size());
    }

    @Test
    void securityGroupOpened() {
        var world = event("x", "AuthorizeSecurityGroupIngress", at(0, 0), "\"requestParameters\":{\"cidrIp\":\"0.0.0.0/0\"}");
        var office = event("y", "AuthorizeSecurityGroupIngress", at(1, 0), "\"requestParameters\":{\"cidrIp\":\"10.0.0.0/8\"}");
        assertEquals(List.of("x"), run(new Rules.SecurityGroupOpenedToWorld(), world, office).stream().map(Finding::actor).toList());
    }

    @Test
    void reconBurst() {
        List<Evidence> ev = new ArrayList<>();
        for (int i = 0; i < 10; i++) ev.add(event("intruder", "ListUsers", at(i, 0), "\"errorCode\":\"AccessDenied\""));
        assertEquals(1, run(new Rules.AccessDeniedBurst(), ev.toArray(Evidence[]::new)).size());
        assertTrue(run(new Rules.AccessDeniedBurst(), ev.subList(0, 9).toArray(Evidence[]::new)).isEmpty());
    }

    @Test
    void sampleIncidentProducesExpectedFindings() {
        List<Finding> f = new Analyzer().analyze(TestData.sample());
        Set<String> rules = f.stream().map(Finding::ruleId).collect(Collectors.toSet());
        assertEquals(Set.of("ROOT-USAGE", "LOGIN-NO-MFA", "BRUTE-FORCE", "LOG-TAMPER", "PRIV-ESC", "SG-OPENED",
                "S3-EXPOSURE", "RECON"), rules);
        assertEquals(Severity.CRITICAL, f.get(0).severity(), "findings are ranked by severity");
        Finding brute = f.stream().filter(x -> x.ruleId().equals("BRUTE-FORCE")).findFirst().orElseThrow();
        assertEquals(Severity.CRITICAL, brute.severity());
        assertTrue(f.stream().filter(x -> !x.ruleId().equals("ROOT-USAGE")).allMatch(x -> x.actor().equals("dev-jenkins")));
    }
}
