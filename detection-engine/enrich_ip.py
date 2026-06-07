"""
SOC Detection & Threat Intelligence Enrichment Engine

Features:

- Elasticsearch Event ID 3 Monitoring

- AbuseIPDB Threat Intelligence Enrichment

- Severity Classification

- MITRE ATT&CK Mapping

- Discord Alerting

- SOAR-Lite Response Workflow

Author: Adeola Quadri
"""

from elasticsearch import Elasticsearch
import requests
import time
import ipaddress
import subprocess

# =========================
# CONFIGURATION
# =========================
ELASTIC_URL = "http://localhost:9200"
ABUSEIPDB_API_KEY = "ac*********************************************************************7"
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/**************************************************************************************k"
INDEX_NAME = "filebeat-*"

# =========================
# WHITELISTED DOMAINS
# =========================
WHITELISTED_DOMAINS = [
    "microsoft.com",
    "google.com",
    "cloudflare.com"
]

# =========================
# CONNECT TO ELASTICSEARCH
# =========================
es = Elasticsearch(ELASTIC_URL)
print("[+] Connecting to Elasticsearch...")
try:
    print(es.info())
    print("[+] Elasticsearch connection successful")
except Exception as e:
    print(f"[ERROR] Elasticsearch connection failed: {e}")
    exit()

# =========================
# DEDUP TRACKER
# =========================
seen_events = set()

# =========================
# IP VALIDATION
# =========================
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

# =========================
# ABUSEIPDB LOOKUP
# =========================
def check_ip_abuse(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        data = response.json()
        if response.status_code != 200 or "data" not in data:
            return None
        return data["data"]
    except Exception as e:
        print(f"[ERROR] AbuseIPDB lookup failed: {e}")
        return None

# =========================
# DISCORD ALERTING
# =========================
def send_discord_alert(message):
    payload = {"content": message}
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)
        print(f"[+] Discord alert sent: {response.status_code}")
    except Exception as e:
        print(f"[ERROR] Discord webhook failed: {e}")

# =========================
# FIREWALL BLOCK FUNCTION
# =========================
def block_ip(ip):
    try:
        print(f"[RESPONSE] Blocking IP: {ip}")
        subprocess.run(["sudo", "ufw", "deny", "from", ip], check=True)
        print(f"[+] Successfully blocked IP: {ip}")
    except Exception as e:
        print(f"[ERROR] Failed to block IP: {e}")

# =========================
# MAIN LOOP
# =========================
print("[+] Starting SOC automation pipeline...")

while True:
    try:
        response = es.search(
            index=INDEX_NAME,
            body={
                "size": 5,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"event.code": "3"}},
                            {"range": {"@timestamp": {"gte": "now-5m"}}}
                        ]
                    }
                }
            }
        )

        hits = response["hits"]["hits"]
        print(f"[DEBUG] Total hits found: {len(hits)}")

        for hit in hits:
            event_id = hit["_id"]
            if event_id in seen_events:
                continue
            seen_events.add(event_id)
            source = hit["_source"]

            hostname = source.get("host", {}).get("name", "unknown-host")
            process_name = source.get("process", {}).get("name") or source.get("winlog", {}).get("event_data", {}).get("Image", "unknown-process")
            destination_ip = source.get("destination", {}).get("ip") or source.get("winlog", {}).get("event_data", {}).get("DestinationIp")

            if not destination_ip or not is_valid_ip(destination_ip):
                continue
            if destination_ip.startswith(("127.", "192.168.", "10.")):
                continue

            abuse_data = check_ip_abuse(destination_ip)
            if not abuse_data:
                continue

            abuse_score = abuse_data.get("abuseConfidenceScore", 0)
            country = abuse_data.get("countryCode", "Unknown")
            isp = abuse_data.get("isp", "Unknown")
            domain = abuse_data.get("domain", "")

            if domain.lower() in WHITELISTED_DOMAINS:
                continue

            # SEVERITY CLASSIFICATION
            if abuse_score >= 75:
                severity = "CRITICAL"
            elif abuse_score >= 50:
                severity = "HIGH"
            elif abuse_score >= 25:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            print(f"[WORKFLOW] Severity classified as: {severity}")

            # LOW
            if severity == "LOW":
                print(f"[WORKFLOW] LOW severity event logged only")

            # MEDIUM
            elif severity == "MEDIUM":
                alert_message = f"""
🟡 MEDIUM Severity Network Alert
🖥 Host: {hostname}
⚙ Process: {process_name}
🌐 Destination IP: {destination_ip}
🔥 Abuse Score: {abuse_score}
🛡 Action: Discord Alert Only
"""
                send_discord_alert(alert_message)

            # HIGH
            elif severity == "HIGH":
                alert_message = f"""
🟠 HIGH Severity Threat Detected
🖥 Host: {hostname}
⚙ Process: {process_name}
🌐 Destination IP: {destination_ip}
🔥 Abuse Score: {abuse_score}
🛡 Response: Simulated Containment
🎯 MITRE: T1049 - Network Connections Discovery
"""
                send_discord_alert(alert_message)

            # CRITICAL
            elif severity == "CRITICAL":
                block_ip(destination_ip)
                alert_message = f"""
🔴 CRITICAL Threat Detected
🖥 Host: {hostname}
⚙ Process: {process_name}
🌐 Destination IP: {destination_ip}
🔥 Abuse Score: {abuse_score}
🚨 Response: AUTOMATED IP BLOCK
🎯 MITRE: T1049 - Network Connections Discovery
"""
                send_discord_alert(alert_message)

    except Exception as e:
        print(f"[ERROR] Main loop error: {e}")

    time.sleep(30)
