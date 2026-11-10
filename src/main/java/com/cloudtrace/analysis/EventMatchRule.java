package com.cloudtrace.analysis;

import com.cloudtrace.model.Evidence;
import com.cloudtrace.model.Finding;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Base class for rules that flag individual events. Matching events are grouped
 * per actor so one noisy actor produces one finding with all its evidence.
 */
public abstract class EventMatchRule implements DetectionRule {

    protected abstract boolean matches(Evidence e);

    protected String describe(String actor, List<Evidence> events) {
        return actor + " performed " + events.size() + " matching event(s): "
                + events.stream().map(Evidence::getEventName).distinct().toList();
    }

    @Override
    public List<Finding> evaluate(List<Evidence> timeline) {
        Map<String, List<Evidence>> byActor = new LinkedHashMap<>();
        for (Evidence e : timeline) {
            if (matches(e)) byActor.computeIfAbsent(e.getActor(), k -> new ArrayList<>()).add(e);
        }
        List<Finding> out = new ArrayList<>();
        byActor.forEach((actor, events) -> out.add(new Finding(null, null, id(), title(), severity(), actor,
                events.get(0).getEventTime(), events.get(events.size() - 1).getEventTime(),
                describe(actor, events), events.stream().map(Evidence::getEventId).toList())));
        return out;
    }
}
