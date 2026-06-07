SOC Telemetry & Threat Detection Pipeline with SOAR-Lite Automation

Executive Summary

This project demonstrates the design and implementation of a Security Operations Center (SOC) telemetry, detection, enrichment, alerting, and response workflow using open-source technologies.

The solution collects endpoint telemetry from a Windows system using Sysmon, forwards logs through Filebeat into Elasticsearch, analyzes network connection events using a custom Python detection engine, enriches indicators with AbuseIPDB threat intelligence, classifies severity levels, maps activity to MITRE ATT&CK techniques, and generates real-time Discord alerts.

To improve deployment consistency and operational realism, the detection engine was containerized using Docker. The project also implements SOAR-lite automation concepts through automated enrichment, severity classification, alerting, and response workflows.

⸻

Project Objectives

The primary objectives of this project were:

* Build a centralized telemetry collection pipeline.
* Monitor Windows endpoint activity using Sysmon.
* Forward logs into Elasticsearch using Filebeat.
* Develop a custom detection engine using Python.
* Integrate external threat intelligence using AbuseIPDB.
* Automate alert generation and severity classification.
* Implement response workflow logic.
* Containerize the detection engine using Docker.
* Demonstrate SOC and Detection Engineering concepts.

⸻

Environment Setup

Windows Endpoint

The Windows endpoint serves as the telemetry source.

Installed Components:

* Sysmon
* PowerShell
* Windows Event Logging

Ubuntu SOC Server

The Ubuntu server hosts:

* Elasticsearch
* Kibana
* Docker
* Python Detection Engine

Docker

Docker was used to package and deploy the detection engine as a portable service.

⸻

Architecture Design

The architecture consists of five major layers:

1. Telemetry Collection

Sysmon collects endpoint telemetry including:

* Process Creation Events
* Network Connections
* DNS Queries
* File Creation Events

2. Log Forwarding

Filebeat forwards Sysmon telemetry from Windows to Elasticsearch.

3. Detection Layer

A custom Python script (enrich_ip.py) continuously queries Elasticsearch for Sysmon Event ID 3 network connection events.

4. Enrichment Layer

Suspicious IP addresses are enriched using AbuseIPDB threat intelligence.

Retrieved intelligence includes:

* Abuse Confidence Score
* Country
* ISP
* Threat Context

5. Alerting and Response Layer

The workflow classifies severity and generates Discord alerts.

Response actions are executed based on severity levels.

⸻

Telemetry Pipeline

Data Flow:

Windows Endpoint
→ Sysmon
→ Filebeat
→ Elasticsearch
→ Kibana

Telemetry is centralized in Elasticsearch and visualized through Kibana.

The primary detection focus is Sysmon Event ID 3, which records outbound network connections.

⸻

Detection Engineering

Detection Name

Suspicious Network Connection Detection

Data Source

Sysmon Event ID 3

Detection Workflow

1. Query Elasticsearch.
2. Search for Event ID 3 logs.
3. Extract destination IP address.
4. Validate IP format.
5. Apply whitelist filtering.
6. Query AbuseIPDB.
7. Calculate severity.
8. Generate alert.

False Positive Reduction

To reduce noise, trusted destinations are excluded.

Examples:

* Microsoft
* Google
* Cloudflare

⸻

Threat Intelligence Enrichment

Threat intelligence enrichment is performed using AbuseIPDB.

Enrichment Data

The following information is collected:

* Abuse Confidence Score
* Country
* ISP
* Domain Information
* Usage Type

Benefits

Threat intelligence enrichment improves:

* Alert context
* Analyst decision-making
* Incident prioritization

⸻

Severity Classification

Threat severity is determined using AbuseIPDB confidence scores.

Severity	Score
LOW	<25
MEDIUM	25-49
HIGH	50-74
CRITICAL	>=75

Example:

Abuse Score: 100

Severity: CRITICAL

⸻

MITRE ATT&CK Mapping

The project maps detections to MITRE ATT&CK techniques.

Examples:

T1049

System Network Connections Discovery

T1046

Network Service Scanning

T1071

Application Layer Protocol

This mapping helps analysts understand adversary behavior and tactics.

⸻

Alerting Workflow

Alerts are generated through Discord webhooks.

Each alert includes:

* Hostname
* Process Name
* Destination IP
* Abuse Score
* Country
* ISP
* Severity
* MITRE ATT&CK Technique
* Response Action

This provides analysts with immediate investigation context.

⸻

Response Workflow

The project implements SOAR-lite response logic.

LOW

Log event only.

MEDIUM

Generate Discord alert.

HIGH

Generate Discord alert and simulated response.

CRITICAL

Generate Discord alert and simulated block action.

Current response actions are intentionally simulated to maintain safe operation within the Dockerized environment.

⸻

Dockerization

The detection engine was containerized using Docker.

Benefits:

* Portability
* Consistent deployment
* Simplified operations
* Easier maintenance

Docker Image Components:

* Ubuntu 22.04
* Python 3
* Elasticsearch Client
* Requests Library

⸻

Attack Simulations

Simulation 1: Network Connection Telemetry

Objective:

Generate Sysmon Event ID 3.

Command:

Test-NetConnection google.com -Port 80

Result:

Telemetry successfully generated and indexed.

⸻

Simulation 2: Threat Intelligence Enrichment

Objective:

Validate AbuseIPDB integration.

Result:

Threat intelligence successfully retrieved and attached to alerts.

⸻

Simulation 3: Alert and Response Workflow

Objective:

Validate end-to-end SOC workflow.

Result:

Detection, enrichment, alerting, and response workflow executed successfully.

⸻

Results

The project successfully demonstrated:

* Endpoint telemetry collection
* Centralized logging
* Detection engineering
* Threat intelligence enrichment
* Severity classification
* MITRE ATT&CK mapping
* Automated alerting
* SOAR-lite response workflows
* Dockerized deployment

⸻

Challenges Encountered

Several challenges were encountered during development:

Elasticsearch Query Tuning

Field mappings required validation to ensure Event ID 3 detection worked correctly.

Threat Intelligence Validation

IP validation was necessary to prevent AbuseIPDB API errors.

False Positive Reduction

Whitelisting was implemented to reduce noise from trusted services.

Docker Privilege Limitations

Firewall response actions required modification due to container restrictions.

⸻

Lessons Learned

* Effective detections require quality telemetry.
* Threat intelligence significantly improves alert context.
* Whitelisting is essential for reducing false positives.
* Detection engineering requires continuous tuning.
* Docker improves deployment consistency.
* Automated workflows improve incident response efficiency.

⸻

Future Improvements

Planned enhancements include:

* VirusTotal enrichment
* TheHive case management integration
* Shuffle SOAR orchestration
* Automated incident creation
* IOC correlation
* Threat hunting dashboards
* Additional detection use cases

⸻

Conclusion

This project successfully demonstrates the implementation of a SOC telemetry, detection, enrichment, alerting, and SOAR-lite automation pipeline using open-source technologies.

The solution showcases practical skills in SIEM engineering, detection engineering, threat intelligence integration, security automation, Docker containerization, and incident response workflows.

The project provides a strong foundation for future expansion into full SOAR orchestration and enterprise-scale security monitoring environments.
