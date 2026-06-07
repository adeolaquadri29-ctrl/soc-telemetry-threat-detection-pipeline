Incident Report

Incident ID: SOC-001

Date: 2026-05-29

Detection Name: Suspicious Network Connection

Source: Sysmon Event ID 3

Host: quedee

Process:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Destination IP:
185.220.101.1

Threat Intelligence Source:
AbuseIPDB

Abuse Score:
100

Country:
Germany (DE)

ISP:
Artikel10 e.V.

Severity:
CRITICAL

MITRE ATT&CK:
T1049 – System Network Connections Discovery

Response Action:
SIMULATED BLOCK

Status:
Resolved

Analyst Notes:

The destination IP was identified as a highly suspicious indicator based on AbuseIPDB intelligence. The event was enriched, classified as CRITICAL, and routed through the response workflow.
