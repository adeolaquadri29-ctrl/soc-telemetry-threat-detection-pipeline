Detection Logic

Detection Name

Suspicious Network Connection

Data Source

Sysmon Event ID 3

Detection Workflow

1. Query Elasticsearch for Event ID 3.
2. Extract destination IP.
3. Validate IP format.
4. Apply whitelist filtering.
5. Query AbuseIPDB.
6. Calculate threat severity.
7. Generate alert.

Severity Levels

LOW: <25

MEDIUM: 25-49

HIGH: 50-74

CRITICAL: >=75

MITRE ATT&CK Mapping

T1049 – System Network Connections Discovery
