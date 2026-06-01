SOC Telemetry & Threat Detection Pipeline

Overview

This project demonstrates the design and implementation of a Security Operations Center (SOC) telemetry, detection, enrichment, alerting, and response pipeline.

The environment collects Windows endpoint telemetry using Sysmon, ships logs through Filebeat into Elasticsearch, enriches suspicious network activity with threat intelligence from AbuseIPDB, and automates alerting and response actions through Python and Docker.

The goal was to simulate core SOC and SOAR capabilities commonly found in enterprise security operations environments.

⸻

Architecture

Windows Endpoint
→ Sysmon
→ Filebeat
→ Elasticsearch
→ Kibana
→ Python Detection Engine
→ AbuseIPDB Enrichment
→ Discord Alerting
→ Automated Response Workflow

⸻

Technologies Used

* Sysmon
* Filebeat
* Elasticsearch
* Kibana
* Python
* Docker
* AbuseIPDB API
* Discord Webhooks
* Ubuntu Linux
* UFW Firewall

⸻

Features

Telemetry Collection

* Windows endpoint monitoring using Sysmon
* Detailed process and network visibility
* Event ID 3 network connection monitoring

Detection Engineering

* Elasticsearch query-based detections
* Network connection analysis
* IP validation
* Alert deduplication
* Whitelisting logic

Threat Intelligence Enrichment

* AbuseIPDB integration
* Abuse confidence scoring
* Threat context enrichment

Alerting

* Real-time Discord notifications
* Severity-based alert generation

Automated Response

* LOW: Log only
* MEDIUM: Alert
* HIGH: Simulated block
* CRITICAL: Automatic UFW block

Dockerization

* Portable deployment
* Consistent runtime environment
* Operational realism

⸻

MITRE ATT&CK Mapping

Technique	Description
T1046	Network Service Scanning
T1071	Application Layer Protocol
T1049	System Network Connections Discovery

⸻

Project Outcomes

* Built an end-to-end SOC telemetry pipeline
* Implemented threat intelligence enrichment
* Developed automated detection workflows
* Integrated automated response actions
* Containerized security operations tooling
* Simulated real-world SOC analyst workflows

⸻

Future Enhancements

* VirusTotal enrichment
* TheHive integration
* Shuffle SOAR orchestration
* Automated case creation
* Additional detection rules
* Threat hunting dashboards
