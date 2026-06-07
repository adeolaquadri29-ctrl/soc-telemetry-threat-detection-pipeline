Simulation 1: Network Connection Telemetry Validation

Objective

Validate that Sysmon Event ID 3 network connection telemetry is generated and successfully ingested into Elasticsearch.

Procedure

1. Open PowerShell on the Windows endpoint.
2. Execute:

Test-NetConnection google.com -Port 80

3. Confirm Sysmon generates Event ID 3.
4. Verify Filebeat forwards the event.
5. Confirm the event is indexed in Elasticsearch.
6. Verify the event appears in Kibana.

Expected Results

* Event ID 3 generated
* Filebeat successfully forwards logs
* Elasticsearch indexes telemetry
* Kibana displays network connection event

Findings

The telemetry pipeline successfully collected and indexed Sysmon Event ID 3 network connection events.
