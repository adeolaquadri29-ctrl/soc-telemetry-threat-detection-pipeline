SOC Telemetry & Threat Detection Pipeline with SOAR-Lite Automation

Overview

This project demonstrates the design and implementation of a Security Operations Center (SOC) telemetry, detection, enrichment, alerting, and response workflow.

The solution collects Windows endpoint telemetry using Sysmon, forwards logs through Filebeat into Elasticsearch, analyzes network connection events using a custom Python detection engine, enriches indicators with AbuseIPDB threat intelligence, classifies threat severity, maps activity to MITRE ATT&CK techniques, and generates real-time Discord alerts.

The detection engine is containerized with Docker to simulate a portable and operational SOC monitoring service.

⸻

Project Architecture
Data Flow

Windows Endpoint → Sysmon → Filebeat → Elasticsearch → Python Detection & Enrichment Engine (enrich_ip.py) → AbuseIPDB → Severity Classification → MITRE ATT&CK Mapping → Discord Alerting → Response Workflow

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

⸻

Key Features

Telemetry Collection

* Endpoint monitoring with Sysmon
* Network connection visibility using Sysmon Event ID 3
* Log forwarding via Filebeat
* Centralized storage in Elasticsearch

Detection Engineering

* Elasticsearch-based detection logic
* Monitoring of suspicious outbound network connections
* IP validation and filtering
* Event deduplication
* Trusted destination whitelisting

Threat Intelligence Enrichment

* AbuseIPDB integration
* Abuse confidence score retrieval
* Country enrichment
* ISP enrichment
* Threat context generation

Severity Classification

Threats are classified based on AbuseIPDB confidence scores:
Severity           Score

LOW                < 25

MEDIUM             25 – 49

HIGH               50 – 74

CRITICAL           ≥ 75

Alerting

* Real-time Discord notifications
* Enriched alert context
* MITRE ATT&CK mapping
* Severity-based response workflow

SOAR-Lite Automation

* Automated enrichment
* Automated severity classification
* Automated alert generation
* Automated response workflow execution

Dockerization

* Containerized detection engine
* Consistent deployment environment
* Improved portability

⸻

Detection Workflow

Sysmon Event ID 3

        ↓

Elasticsearch Query

        ↓

Extract Destination IP

        ↓

Validate IP Address

        ↓

Apply Whitelist

        ↓

AbuseIPDB Lookup

        ↓

Threat Enrichment

        ↓

Severity Classification

        ↓

MITRE ATT&CK Mapping

        ↓

Discord Alert

        ↓

Response Workflow

Threat Intelligence Enrichment Example

The detection engine enriches suspicious network connections with AbuseIPDB intelligence.

Example Alert

Detection: Suspicious Network Connection

Host: quedee

Process:

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Destination IP:

185.220.101.1

Abuse Score:

100

Country:

DE

ISP:

Artikel10 e.V.

Severity:

CRITICAL

Response:

SIMULATED BLOCK

MITRE ATT&CK:

T1049 - System Network Connections Discovery

MITRE ATT&CK Mapping

Technique    Description 
T1049        System Network Connections Discovery

T1046        Network Service Scanning

T1071        Application Layer Protocol

Attack Simulations

Simulation 1 — Network Connection Telemetry

Objective:

Generate Sysmon Event ID 3 telemetry and validate log ingestion.

Example Command:Test-NetConnection google.com -Port 80
Test-NetConnection 45.95.147.236 -Port 443

Expected Outcome:

* Sysmon generates Event ID 3
* Filebeat ships telemetry
* Elasticsearch indexes event
* Event visible in Kibana

⸻

Simulation 2 — Threat Intelligence Enrichment

Objective:

Validate AbuseIPDB enrichment workflow.

Expected Outcome:

* IP extracted from telemetry
* AbuseIPDB queried
* Threat context returned
* Severity assigned

⸻

Simulation 3 — Alert & Response Workflow

Objective:

Validate end-to-end SOC workflow.

Expected Outcome:

* Detection triggered
* Alert enriched
* Discord notification generated
* Response workflow executed

Screenshots 

Architecture
Sysmon Event ID 3 in Kibana
Detection & Enrichment Engine
Discord Alert
Dockerized Deployment 

Skills Demonstrated

* Security Operations Center (SOC) Monitoring
* Detection Engineering
* Threat Intelligence Enrichment
* Security Automation
* Incident Response Workflows
* SIEM Engineering
* Elasticsearch
* Kibana
* Sysmon
* Filebeat
* Python Development
* Docker
* Linux Administration
* MITRE ATT&CK Mapping

⸻

Future Enhancements

* VirusTotal integration
* TheHive incident management
* Shuffle SOAR orchestration
* Automated case creation
* IOC correlation
* Additional detection use cases
* Threat hunting dashboards

⸻

Lessons Learned

* Effective detection depends on high-quality telemetry.
* Threat intelligence enrichment improves alert context and prioritization.
* Docker simplifies deployment and operational consistency.
* Automated workflows accelerate incident response.
* Detection engineering requires continuous tuning to reduce false positives.

⸻

Author

Adeola Quadri

Cybersecurity Analyst | SOC & Detection Engineering Enthusiast

GitHub: https://github.com/adeolaquadri29-ctrl
