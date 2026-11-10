package com.cloudtrace.collect;

import com.cloudtrace.model.Evidence;
import com.cloudtrace.model.EvidenceSource;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.services.cloudtrail.CloudTrailClient;
import software.amazon.awssdk.services.cloudtrail.model.Event;
import software.amazon.awssdk.services.cloudtrail.model.LookupAttributeKey;
import software.amazon.awssdk.services.cloudtrail.model.LookupEventsRequest;
import software.amazon.awssdk.services.cloudtrail.model.LookupEventsResponse;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CloudTrailApiCollectorTest {

    private static Event event(String id, String name) {
        return Event.builder().eventId(id).eventName(name).cloudTrailEvent(
                "{\"eventID\":\"" + id + "\",\"eventName\":\"" + name + "\",\"eventTime\":\"2026-10-14T09:00:00Z\","
                        + "\"userIdentity\":{\"type\":\"IAMUser\",\"userName\":\"alice\"}}").build();
    }

    @Test
    void pagesThroughLookupEventsAndFiltersByUser() throws Exception {
        CloudTrailClient client = mock(CloudTrailClient.class);
        when(client.lookupEventsPaginator(any(LookupEventsRequest.class))).thenCallRealMethod();
        when(client.lookupEvents(any(LookupEventsRequest.class)))
                .thenReturn(LookupEventsResponse.builder().events(event("a", "CreateUser")).nextToken("p2").build())
                .thenReturn(LookupEventsResponse.builder().events(event("b", "DeleteUser")).build());

        Instant from = Instant.parse("2026-10-14T00:00:00Z"), to = Instant.parse("2026-10-15T00:00:00Z");
        List<Evidence> out = new CloudTrailApiCollector(client, "alice").collect(from, to);

        assertEquals(List.of("a", "b"), out.stream().map(Evidence::getEventId).toList());
        assertTrue(out.stream().allMatch(e -> e.getSource() == EvidenceSource.CLOUDTRAIL_API));
        ArgumentCaptor<LookupEventsRequest> req = ArgumentCaptor.forClass(LookupEventsRequest.class);
        verify(client, times(2)).lookupEvents(req.capture());
        LookupEventsRequest first = req.getAllValues().get(0);
        assertEquals(from, first.startTime());
        assertEquals(LookupAttributeKey.USERNAME, first.lookupAttributes().get(0).attributeKey());
        assertEquals("p2", req.getAllValues().get(1).nextToken());
    }

    @Test
    void wrapsAwsErrors() {
        CloudTrailClient client = mock(CloudTrailClient.class);
        when(client.lookupEventsPaginator(any(LookupEventsRequest.class))).thenCallRealMethod();
        when(client.lookupEvents(any(LookupEventsRequest.class))).thenThrow(new RuntimeException("throttled"));
        var ex = assertThrows(EvidenceCollector.CollectionException.class,
                () -> new CloudTrailApiCollector(client, null).collect(Instant.EPOCH, Instant.now()));
        assertTrue(ex.getMessage().contains("throttled"));
    }
}
