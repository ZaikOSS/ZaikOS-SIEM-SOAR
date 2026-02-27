#!/usr/bin/env python3
"""
ZaikOS Threat Intelligence Analyzer
------------------------------------
Queries VirusTotal + AbuseIPDB, prints a structured verdict,
then triggers automated firewall response via SSH if needed.
"""

import sys
import os
import json
import time
import datetime
import logging
import socket
import requests
import paramiko
from dataclasses import dataclass, asdict
from typing import Optional

# Force UTF-8 output on Windows to avoid cp1252 UnicodeEncodeError
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ── CONFIG ────────────────────────────────────────────────────────────────────
VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY", "key_not_set")  # Must be set in environment for real use
ABUSEIPDB_API_KEY  = os.getenv("ABUSE_API_KEY", "key_not_set")  # Must be set in environment for real use

TARGET_HOST  = os.getenv("TARGET_HOST",  "ip_here")
TARGET_PORT  = int(os.getenv("TARGET_PORT", "22"))
TARGET_USER  = os.getenv("TARGET_USER",  "user")
TARGET_PASS  = os.getenv("TARGET_PASS",  "password")

# A known-malicious IP to substitute when a private IP is detected (lab only)
SPOOF_IP = "185.220.101.7"

if sys.platform == "win32":
    LOG_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
else:
    LOG_DIR  = "/var/ossec/logs"

os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "analyzer.log")

# Thresholds
VT_MALICIOUS_THRESHOLD    = 1   # flag if >= N vendors say malicious
ABUSE_CONFIDENCE_THRESHOLD = 25  # flag if AbuseIPDB confidence >= N%

# -- LOGGING -------------------------------------------------------------------
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("zaikos.analyzer")

def p(msg: str):
    """Print and log simultaneously."""
    print(msg, flush=True)
    log.info(msg)

# -- DATA CLASSES --------------------------------------------------------------
@dataclass
class ThreatReport:
    ip: str
    query_ip: str          # may differ if spoofed
    timestamp: str
    is_private: bool

    vt_malicious: Optional[int] = None
    vt_suspicious: Optional[int] = None
    vt_total: Optional[int] = None
    vt_country: Optional[str] = None
    vt_error: Optional[str] = None

    abuse_confidence: Optional[int] = None
    abuse_total_reports: Optional[int] = None
    abuse_country: Optional[str] = None
    abuse_isp: Optional[str] = None
    abuse_error: Optional[str] = None

    verdict: Optional[str] = None
    action_taken: Optional[str] = None
    block_success: Optional[bool] = None

# -- HELPERS -------------------------------------------------------------------
def is_private_ip(ip: str) -> bool:
    try:
        addr = socket.inet_aton(ip)
    except socket.error:
        return False
    parts = [int(b) for b in ip.split(".")]
    return (
        parts[0] == 10 or
        (parts[0] == 172 and 16 <= parts[1] <= 31) or
        (parts[0] == 192 and parts[1] == 168) or
        parts[0] == 127
    )

def api_get(url: str, headers: dict, params: dict = None, retries: int = 3) -> Optional[dict]:
    """GET with simple retry + exponential back-off."""
    for attempt in range(retries):
        try:
            r = requests.get(url, headers=headers, params=params, timeout=10)
            if r.status_code == 429:
                wait = 2 ** attempt
                p(f"[!] Rate limited by API, waiting {wait}s...")
                time.sleep(wait)
                continue
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            if attempt == retries - 1:
                raise
            time.sleep(1.5 * (attempt + 1))
    return None

# -- INTELLIGENCE QUERIES ------------------------------------------------------
def query_virustotal(ip: str, report: ThreatReport):
    p(f"[+] Querying VirusTotal for {ip}...")
    try:
        data = api_get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
        )
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        report.vt_malicious  = stats.get("malicious", 0)
        report.vt_suspicious = stats.get("suspicious", 0)
        report.vt_total      = sum(stats.values())
        report.vt_country    = attrs.get("country", "N/A")
        p(f"[VT] {report.vt_malicious} malicious / {report.vt_suspicious} suspicious "
          f"out of {report.vt_total} vendors | Country: {report.vt_country}")
    except Exception as e:
        report.vt_error = str(e)
        p(f"[!] VirusTotal error: {e}")


def query_abuseipdb(ip: str, report: ThreatReport):
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_KEY_HERE":
        p("[!] AbuseIPDB key not configured, skipping.")
        return
    p(f"[+] Querying AbuseIPDB for {ip}...")
    try:
        data = api_get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
        )
        d = data["data"]
        report.abuse_confidence   = d.get("abuseConfidenceScore", 0)
        report.abuse_total_reports = d.get("totalReports", 0)
        report.abuse_country       = d.get("countryCode", "N/A")
        report.abuse_isp           = d.get("isp", "N/A")
        p(f"[AB] Confidence: {report.abuse_confidence}% | "
          f"Reports: {report.abuse_total_reports} | "
          f"ISP: {report.abuse_isp} | Country: {report.abuse_country}")
    except Exception as e:
        report.abuse_error = str(e)
        p(f"[!] AbuseIPDB error: {e}")

# -- FIREWALL BLOCK ------------------------------------------------------------
def block_attacker(ip: str, report: ThreatReport):
    p(f"\n[SYSTEM DEFENSE] Initiating automated firewall block for {ip}...")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(TARGET_HOST, port=TARGET_PORT, username=TARGET_USER,
                    password=TARGET_PASS, timeout=8, banner_timeout=8)

        # Check if rule already exists to avoid duplicates
        _, out, _ = ssh.exec_command(f"sudo ufw status | grep -c '{ip}'")
        already_blocked = out.read().decode().strip()

        if already_blocked != "0":
            p(f"[INFO] {ip} already blocked on target machine.")
            report.action_taken = "already_blocked"
            report.block_success = True
            ssh.close()
            return

        # Block inbound + outbound for the attacker
        cmd = (
            f"echo '{TARGET_PASS}' | sudo -S ufw deny from {ip} to any && "
            f"echo '{TARGET_PASS}' | sudo -S ufw deny out to {ip}"
        )
        _, stdout, stderr = ssh.exec_command(cmd)
        time.sleep(2)
        err = stderr.read().decode().strip()

        if err and "already" not in err.lower():
            raise RuntimeError(err)

        p(f"[SUCCESS] {ip} has been permanently blocked on {TARGET_HOST}.")
        report.action_taken = "firewall_block"
        report.block_success = True
        ssh.close()

    except Exception as e:
        p(f"[FAILED] Could not execute firewall block. Error: {e}")
        report.action_taken = "block_failed"
        report.block_success = False
        log.exception("Firewall block failed")

# -- VERDICT LOGIC -------------------------------------------------------------
def determine_verdict(report: ThreatReport) -> str:
    vt_hit    = (report.vt_malicious or 0) >= VT_MALICIOUS_THRESHOLD
    abuse_hit = (report.abuse_confidence or 0) >= ABUSE_CONFIDENCE_THRESHOLD

    if vt_hit and abuse_hit:
        return "CRITICAL RISK (Confirmed Malicious - VT + AbuseIPDB)"
    elif vt_hit:
        return "CRITICAL RISK (Known Attacker - VirusTotal)"
    elif abuse_hit:
        return f"HIGH RISK (AbuseIPDB Confidence: {report.abuse_confidence}%)"
    elif (report.vt_suspicious or 0) > 0:
        return "MEDIUM RISK (Suspicious - VirusTotal)"
    else:
        return "CLEAN (No known malicious activity)"

# -- PRINT FINAL REPORT --------------------------------------------------------
def print_report(report: ThreatReport):
    sep = "-" * 50
    p(sep)
    p(f"[VERDICT]: {report.verdict}")
    p(sep)
    p(f"[TARGET IP]: {report.ip}")
    if report.is_private:
        p(f"[QUERY IP]:  {report.query_ip} (lab spoof)")

    if report.vt_malicious is not None:
        p(f"[VT REPORT]: {report.vt_malicious} malicious vendors flagged this IP as malicious.")
        if report.vt_country:
            p(f"[VT ORIGIN]: {report.vt_country}")

    if report.abuse_confidence is not None:
        p(f"[ABUSE]:     Confidence {report.abuse_confidence}% | "
          f"{report.abuse_total_reports} reports | {report.abuse_isp}")

    if report.action_taken:
        if report.block_success:
            p(f"[ACTION]:    SUCCESS - Firewall rule added on {TARGET_HOST}")
        else:
            p(f"[ACTION]:    FAILED  - Manual intervention required")
    else:
        p("[ACTION]:    Continue Monitoring.")
    p(sep)

    # Save JSON report to /tmp for potential future use
    try:
        tmp_dir = LOG_DIR  # reuse same logs folder for JSON reports
        report_path = os.path.join(tmp_dir, f"zaikos_{report.ip.replace('.','_')}_{int(time.time())}.json")
        with open(report_path, "w") as f:
            json.dump(asdict(report), f, indent=2)
        log.info(f"Report saved: {report_path}")
    except Exception:
        pass

# -- MAIN ----------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("[ERROR] Usage: analyzer.py <ip_address>")
        sys.exit(1)

    original_ip = sys.argv[1].strip()
    private     = is_private_ip(original_ip)
    query_ip    = SPOOF_IP if private else original_ip

    report = ThreatReport(
        ip=original_ip,
        query_ip=query_ip,
        timestamp=datetime.datetime.now().isoformat(),
        is_private=private,
    )

    p(f"[*] ZaikOS Threat Intelligence Engine v2.0")
    p(f"[*] Target IP  : {original_ip}")
    if private:
        p(f"[!] Private IP -- querying APIs with spoofed IP: {query_ip}")
    p(f"[*] Timestamp  : {report.timestamp}")
    p("")

    # Run intelligence queries
    query_virustotal(query_ip, report)
    query_abuseipdb(query_ip, report)

    # Determine verdict
    report.verdict = determine_verdict(report)

    # Automated response
    needs_block = (
        "CRITICAL RISK" in report.verdict or
        "HIGH RISK" in report.verdict
    )
    if needs_block:
        block_attacker(original_ip, report)

    # Print final structured report
    print_report(report)


if __name__ == "__main__":
    main()