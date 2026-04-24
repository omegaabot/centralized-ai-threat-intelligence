from __future__ import annotations

import hashlib
import random
import re
from datetime import datetime, timedelta
from typing import Dict, List

IOC_TYPES = ["Domain", "IP", "URL", "Hash"]
STATUS_OPTIONS = ["Open", "Investigating", "Closed"]

THREAT_LABELS = {
    "Domain": ["Phishing", "Command and Control", "Typosquatting", "Malware Delivery"],
    "IP": ["Botnet", "Brute Force", "Malware Beacon", "Suspicious Scanner"],
    "URL": ["Credential Harvesting", "Phishing", "Drive-by Download", "Exploit Kit"],
    "Hash": ["Ransomware", "Loader", "Trojan", "Backdoor"],
    "Unknown": ["Suspicious Activity"],
}

FEED_SOURCES = [
    "OpenCTI Mirror",
    "MISP Sync",
    "Abuse Feed",
    "SOC Analyst Import",
    "Dark Web Pulse",
]

AUTO_FEED_IOCS = [
    "cdn-auth-check.net/login",
    "198.51.100.42",
    "secure-portal-check.com",
    "http://secure-payments-alert.net/update",
    "45.77.12.9",
    "a7e4c2d1290f5aa998efab22cd18ef01",
    "mail-office365-verify.org",
    "103.24.77.200",
    "http://hr-benefits-sync.com/employee-login",
    "7f4a9bc11834ef1093bc9019ab77d11e",
]


def classify_ioc_type(ioc: str) -> str:
    cleaned = ioc.strip().lower()
    if cleaned.startswith(("http://", "https://")):
        return "URL"
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", cleaned):
        return "IP"
    if re.fullmatch(r"[a-f0-9]{32,64}", cleaned):
        return "Hash"
    if "." in cleaned:
        return "Domain"
    return "Unknown"


def risk_label(score: int) -> str:
    if score >= 75:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"


def confidence_label(score: int) -> str:
    if score >= 85:
        return "Very High"
    if score >= 70:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"


def _seeded_random(ioc: str) -> random.Random:
    digest = hashlib.sha256(ioc.encode("utf-8")).hexdigest()
    return random.Random(int(digest[:16], 16))


def analyze_ioc(ioc: str, selected_type: str | None = None) -> Dict[str, str | int]:
    ioc_value = ioc.strip()
    detected_type = classify_ioc_type(ioc_value)
    final_type = detected_type if not selected_type or selected_type == "Auto Detect" else selected_type
    rng = _seeded_random(ioc_value)

    score_ranges = {
        "URL": (72, 96),
        "Domain": (45, 88),
        "IP": (58, 92),
        "Hash": (80, 99),
        "Unknown": (30, 60),
    }
    low, high = score_ranges.get(final_type, (30, 60))
    score = rng.randint(low, high)

    if any(keyword in ioc_value.lower() for keyword in ["login", "verify", "secure", "update", "alert"]):
        score = min(99, score + rng.randint(4, 10))
    if final_type == "Hash" and len(ioc_value) >= 32:
        score = max(score, 88)

    threat = rng.choice(THREAT_LABELS.get(final_type, THREAT_LABELS["Unknown"]))
    return {
        "ioc": ioc_value,
        "type": final_type,
        "threat": threat,
        "confidence": confidence_label(score),
        "score": score,
        "risk": risk_label(score),
    }


def build_demo_seed_data() -> List[Dict[str, str | int]]:
    now = datetime.utcnow()
    sample_iocs = [
        ("evil-auth-gateway.com", "Threat Feed", "Open"),
        ("91.240.118.172", "MISP Sync", "Investigating"),
        ("http://update-office-verify.net/signin", "OpenCTI Mirror", "Open"),
        ("f0a12b9987cc12ee44ad0b772090ab56", "Malware Sandbox", "Investigating"),
        ("payroll-access-check.org", "SOC Analyst Import", "Closed"),
        ("172.16.45.67", "Abuse Feed", "Open"),
        ("https://mail-gateway-reset.com/auth", "Dark Web Pulse", "Open"),
        ("microsoft-security-team.co", "OpenCTI Mirror", "Investigating"),
        ("8a33bc90f1749912ccba7811efab9920", "Malware Sandbox", "Closed"),
        ("198.51.100.14", "Threat Feed", "Open"),
        ("citrix-vpn-auth.net", "Dark Web Pulse", "Investigating"),
        ("http://support-session-check.net/portal", "MISP Sync", "Open"),
    ]

    seeded: List[Dict[str, str | int]] = []
    for index, (ioc, source, status) in enumerate(sample_iocs):
        analysis = analyze_ioc(ioc)
        created_at = now - timedelta(hours=index * 6 + 1)
        seeded.append(
            {
                **analysis,
                "status": status,
                "source": source,
                "created_at": created_at.isoformat(),
                "updated_at": created_at.isoformat(),
            }
        )
    return seeded


def generate_auto_feed_entries(count: int = 8) -> List[Dict[str, str | int]]:
    now = datetime.utcnow()
    entries: List[Dict[str, str | int]] = []
    for index in range(max(1, count)):
        ioc = AUTO_FEED_IOCS[index % len(AUTO_FEED_IOCS)]
        analysis = analyze_ioc(ioc)
        timestamp = now - timedelta(minutes=index * 13)
        entries.append(
            {
                **analysis,
                "status": random.choice(["Open", "Open", "Investigating"]),
                "source": random.choice(FEED_SOURCES),
                "created_at": timestamp.isoformat(),
                "updated_at": timestamp.isoformat(),
            }
        )
    return entries
