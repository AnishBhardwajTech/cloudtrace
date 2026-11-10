package com.cloudtrace.collect;

import com.cloudtrace.model.Evidence;
import com.cloudtrace.model.EvidenceSource;
import software.amazon.awssdk.services.cloudtrail.CloudTrailClient;
import software.amazon.awssdk.services.cloudtrail.model.Event;
import software.amazon.awssdk.services.cloudtrail.model.LookupAttribute;
import software.amazon.awssdk.services.cloudtrail.model.LookupAttributeKey;
import software.amazon.awssdk.services.cloudtrail.model.LookupEventsRequest;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Collects the last 90 days of management events through the CloudTrail
 * LookupEvents API (AWS SDK for Java v2), optionally filtered by user name.
 */
public class CloudTrailApiCollector implements EvidenceCollector {
    private final CloudTrailClient client;
    private final String username;
    private final CloudTrailRecordParser parser = new CloudTrailRecordParser();

    public CloudTrailApiCollector(CloudTrailClient client, String username) {
        this.client = client;
        this.username = username;
    }

    @Override
    public List<Evidence> collect(Instant from, Instant to) throws CollectionException {
        LookupEventsRequest.Builder req = LookupEventsRequest.builder().startTime(from).endTime(to).maxResults(50);
        if (username != null) {
            req.lookupAttributes(LookupAttribute.builder()
                    .attributeKey(LookupAttributeKey.USERNAME).attributeValue(username).build());
        }
        List<Evidence> out = new ArrayList<>();
        try {
            for (Event e : client.lookupEventsPaginator(req.build()).events()) {
                out.add(parser.parseRecord(e.cloudTrailEvent(), EvidenceSource.CLOUDTRAIL_API));
            }
        } catch (Exception ex) {
            throw new CollectionException("CloudTrail lookup failed: " + ex.getMessage(), ex);
        }
        return out;
    }

    @Override
    public String describe() {
        return "CloudTrail LookupEvents API" + (username != null ? " (user " + username + ")" : "");
    }
}
