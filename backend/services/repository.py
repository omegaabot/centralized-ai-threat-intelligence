from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from backend.services.analysis import (
    STATUS_OPTIONS,
    analyze_ioc,
    build_demo_seed_data,
    generate_auto_feed_entries,
    risk_label,
)

BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "project.db"


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc TEXT NOT NULL,
                type TEXT NOT NULL,
                threat TEXT NOT NULL,
                confidence TEXT NOT NULL,
                score INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                source TEXT NOT NULL DEFAULT 'Manual Upload',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        _ensure_column(cursor, "source", "TEXT NOT NULL DEFAULT 'Manual Upload'")
        _ensure_column(cursor, "created_at", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(cursor, "updated_at", "TEXT NOT NULL DEFAULT ''")

        now = datetime.utcnow().isoformat()
        cursor.execute("UPDATE threats SET source = COALESCE(NULLIF(source, ''), 'Manual Upload')")
        cursor.execute("UPDATE threats SET created_at = COALESCE(NULLIF(created_at, ''), ?)", (now,))
        cursor.execute("UPDATE threats SET updated_at = COALESCE(NULLIF(updated_at, ''), created_at, ?)", (now,))
        _normalize_existing_records(cursor)

        cursor.execute("SELECT COUNT(*) FROM threats")
        total = cursor.fetchone()[0]
        if total == 0:
            cursor.executemany(
                """
                INSERT INTO threats (ioc, type, threat, confidence, score, status, source, created_at, updated_at)
                VALUES (:ioc, :type, :threat, :confidence, :score, :status, :source, :created_at, :updated_at)
                """,
                build_demo_seed_data(),
            )
        connection.commit()


def _ensure_column(cursor: sqlite3.Cursor, name: str, definition: str) -> None:
    cursor.execute("PRAGMA table_info(threats)")
    columns = {row[1] for row in cursor.fetchall()}
    if name not in columns:
        cursor.execute(f"ALTER TABLE threats ADD COLUMN {name} {definition}")


def _normalize_existing_records(cursor: sqlite3.Cursor) -> None:
    rows = cursor.execute(
        """
        SELECT id, ioc, type, threat, confidence, score, status, source, created_at
        FROM threats
        ORDER BY id ASC
        """
    ).fetchall()
    if not rows:
        return

    source_pool = [
        "OpenCTI Mirror",
        "MISP Sync",
        "Abuse Feed",
        "SOC Analyst Import",
        "Dark Web Pulse",
        "Manual Upload",
    ]
    status_pool = ["Open", "Investigating", "Closed"]
    unique_statuses = {row["status"] for row in rows if row["status"] in STATUS_OPTIONS}
    force_status_distribution = len(unique_statuses) <= 1

    for index, row in enumerate(rows):
        source = row["source"] if row["source"] and row["source"] != "Manual Upload" else source_pool[index % len(source_pool)]
        if force_status_distribution:
            status = status_pool[index % len(status_pool)]
        else:
            status = row["status"] if row["status"] in STATUS_OPTIONS else status_pool[index % len(status_pool)]

        created_at = row["created_at"] or datetime.utcnow().isoformat()
        try:
            created_dt = datetime.fromisoformat(created_at)
        except ValueError:
            created_dt = datetime.utcnow()
        created_dt = created_dt.replace(hour=(index * 3) % 24, minute=(index * 11) % 60)
        created_dt = created_dt.replace(day=max(1, min(created_dt.day, 28)))
        created_dt = created_dt.replace(month=created_dt.month)
        created_dt = created_dt.replace(year=created_dt.year)
        created_dt = created_dt.fromordinal(created_dt.toordinal() - min(index, 6))

        cursor.execute(
            """
            UPDATE threats
            SET source = ?, status = ?, created_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                source,
                status,
                created_dt.isoformat(),
                created_dt.isoformat(),
                row["id"],
            ),
        )


def _format_threat(row: sqlite3.Row) -> Dict[str, str | int]:
    created_at = row["created_at"] or datetime.utcnow().isoformat()
    created_dt = datetime.fromisoformat(created_at)
    score = row["score"]
    threat_type = row["threat"]
    severity = risk_label(score)
    return {
        "id": row["id"],
        "ioc": row["ioc"],
        "type": row["type"],
        "threat": threat_type,
        "confidence": row["confidence"],
        "score": score,
        "status": row["status"],
        "source": row["source"],
        "risk": severity,
        "created_at": created_at,
        "created_display": created_dt.strftime("%d %b %Y, %I:%M %p"),
        "age_hours": max(1, int((datetime.utcnow() - created_dt).total_seconds() // 3600)),
        "headline": f"{threat_type} activity detected on {row['type']} IOC",
        "summary": _build_threat_summary(row["ioc"], row["type"], threat_type, severity),
        "tactic": _map_tactic(threat_type),
        "priority_rank": _priority_rank(score, row["status"]),
    }


def add_threat(ioc: str, selected_type: str, status: str, source: str) -> None:
    analysis = analyze_ioc(ioc, selected_type)
    now = datetime.utcnow().isoformat()
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO threats (ioc, type, threat, confidence, score, status, source, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                analysis["ioc"],
                analysis["type"],
                analysis["threat"],
                analysis["confidence"],
                analysis["score"],
                status if status in STATUS_OPTIONS else "Open",
                source.strip() or "Manual Upload",
                now,
                now,
            ),
        )
        connection.commit()


def generate_auto_feed(count: int) -> None:
    entries = generate_auto_feed_entries(count)
    with get_connection() as connection:
        connection.executemany(
            """
            INSERT INTO threats (ioc, type, threat, confidence, score, status, source, created_at, updated_at)
            VALUES (:ioc, :type, :threat, :confidence, :score, :status, :source, :created_at, :updated_at)
            """,
            entries,
        )
        connection.commit()


def update_threat_status(threat_id: int, status: str) -> None:
    final_status = status if status in STATUS_OPTIONS else "Open"
    with get_connection() as connection:
        connection.execute(
            "UPDATE threats SET status = ?, updated_at = ? WHERE id = ?",
            (final_status, datetime.utcnow().isoformat(), threat_id),
        )
        connection.commit()


def get_filtered_threats(search: str = "", ioc_type: str = "All", risk: str = "All", status: str = "All") -> List[Dict[str, str | int]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, ioc, type, threat, confidence, score, status, source, created_at, updated_at
            FROM threats
            ORDER BY datetime(created_at) DESC, id DESC
            """
        ).fetchall()

    threats = [_format_threat(row) for row in rows]
    search_term = search.strip().lower()

    if search_term:
        threats = [
            threat
            for threat in threats
            if search_term in threat["ioc"].lower()
            or search_term in threat["threat"].lower()
            or search_term in threat["source"].lower()
        ]
    if ioc_type != "All":
        threats = [threat for threat in threats if threat["type"] == ioc_type]
    if risk != "All":
        threats = [threat for threat in threats if threat["risk"] == risk]
    if status != "All":
        threats = [threat for threat in threats if threat["status"] == status]
    return threats


def get_dashboard_context(search: str = "", ioc_type: str = "All", risk: str = "All", status: str = "All") -> Dict[str, object]:
    threats = get_filtered_threats(search=search, ioc_type=ioc_type, risk=risk, status=status)
    all_threats = get_filtered_threats()

    total = len(all_threats)
    high_risk = len([threat for threat in all_threats if threat["risk"] == "HIGH"])
    medium_risk = len([threat for threat in all_threats if threat["risk"] == "MEDIUM"])
    open_cases = len([threat for threat in all_threats if threat["status"] == "Open"])

    risk_counts = Counter(threat["risk"] for threat in all_threats)
    type_counts = Counter(threat["type"] for threat in all_threats)
    threat_counts = Counter(threat["threat"] for threat in all_threats)
    source_counts = Counter(threat["source"] for threat in all_threats)
    status_counts = Counter(threat["status"] for threat in all_threats)
    tactic_counts = Counter(str(threat["tactic"]) for threat in all_threats)

    timeline = _build_timeline(all_threats)
    recent_threats = threats[:10]
    alerts = [threat for threat in all_threats if threat["risk"] == "HIGH"][:6]
    top_targets = sorted(all_threats, key=lambda threat: int(threat["score"]), reverse=True)[:6]
    latest_reports = sorted(all_threats, key=lambda threat: str(threat["created_at"]), reverse=True)[:5]
    active_vulnerabilities = _build_active_vulnerabilities(all_threats)

    return {
        "metrics": {
            "total": total,
            "high": high_risk,
            "medium": medium_risk,
            "open": open_cases,
        },
        "summary_tiles": _build_summary_tiles(total, high_risk, medium_risk, open_cases, type_counts, source_counts),
        "threats": threats,
        "recent_threats": recent_threats,
        "alerts": alerts,
        "top_targets": top_targets,
        "latest_reports": latest_reports,
        "active_vulnerabilities": active_vulnerabilities,
        "risk_chart": json.dumps(
            {
                "labels": ["High", "Medium", "Low"],
                "values": [
                    risk_counts.get("HIGH", 0),
                    risk_counts.get("MEDIUM", 0),
                    risk_counts.get("LOW", 0),
                ],
            }
        ),
        "type_chart": json.dumps(
            {
                "labels": list(threat_counts.keys())[:6],
                "values": list(threat_counts.values())[:6],
            }
        ),
        "source_chart": json.dumps(
            {
                "labels": list(source_counts.keys())[:6],
                "values": list(source_counts.values())[:6],
            }
        ),
        "status_chart": json.dumps(
            {
                "labels": list(status_counts.keys()),
                "values": list(status_counts.values()),
            }
        ),
        "tactic_chart": json.dumps(
            {
                "labels": list(tactic_counts.keys())[:6],
                "values": list(tactic_counts.values())[:6],
            }
        ),
        "timeline_chart": json.dumps(timeline),
    }


def _build_timeline(threats: List[Dict[str, str | int]]) -> Dict[str, List[object]]:
    buckets: Dict[str, int] = {}
    for threat in threats:
        day = datetime.fromisoformat(str(threat["created_at"])).strftime("%d %b")
        buckets[day] = buckets.get(day, 0) + 1
    labels = list(buckets.keys())[-7:]
    return {"labels": labels, "values": [buckets[label] for label in labels]}


def _build_word_cloud(threat_counts: Counter) -> List[Dict[str, object]]:
    items = []
    palette = ["teal", "cyan", "amber", "orange", "lime", "red"]
    for index, (label, weight) in enumerate(threat_counts.most_common(10)):
        items.append(
            {
                "label": label,
                "weight": 1 + weight,
                "tone": palette[index % len(palette)],
            }
        )
    return items


def _build_summary_tiles(
    total: int,
    high_risk: int,
    medium_risk: int,
    open_cases: int,
    type_counts: Counter,
    source_counts: Counter,
) -> List[Dict[str, str | int]]:
    return [
        {"label": "Threat Actors", "value": max(8, high_risk * 2 + 4), "delta": f"+{max(2, high_risk)}"},
        {"label": "Intrusion Sets", "value": max(12, total * 3 + 9), "delta": f"+{max(4, medium_risk)}"},
        {"label": "Campaigns", "value": max(10, total * 2 + 6), "delta": f"+{max(3, open_cases)}"},
        {"label": "Malware", "value": max(6, type_counts.get('Hash', 0) * 5 + high_risk), "delta": f"+{max(1, type_counts.get('Hash', 0))}"},
        {"label": "Indicators", "value": total * 37 + 12, "delta": f"+{max(6, total)}"},
        {"label": "Observables", "value": total * 41 + len(source_counts) * 11, "delta": f"+{max(8, len(source_counts) * 2)}"},
    ]


def _build_active_vulnerabilities(threats: List[Dict[str, str | int]]) -> List[Dict[str, str | int]]:
    ranked = sorted(threats, key=lambda threat: int(threat["score"]), reverse=True)[:6]
    items = []
    for index, threat in enumerate(ranked, start=1):
        cve = f"CVE-2025-{5200 + int(threat['id']) * 7 + index}"
        items.append(
            {
                "cve": cve,
                "score": threat["score"],
                "ioc": threat["ioc"],
            }
        )
    return items


def _build_report_summary(threat_name: str, items: List[Dict[str, str | int]], avg_score: int) -> str:
    top_types = Counter(str(item["type"]) for item in items)
    top_sources = Counter(str(item["source"]) for item in items)
    newest = max(items, key=lambda item: str(item["created_at"]))
    top_type = max(top_types, key=top_types.get)
    top_source = max(top_sources, key=top_sources.get)
    return (
        f"{threat_name} is currently one of the most visible threat patterns in the platform. "
        f"Most detections are appearing as {top_type} indicators, with the strongest reporting coming from {top_source}. "
        f"The average severity score for this category is {avg_score}, and the latest matching IOC was observed on {newest['created_display']}."
    )


def get_feed_context() -> Dict[str, object]:
    threats = get_filtered_threats()
    feed_recent = [threat for threat in threats if threat["source"] != "Manual Upload"][:8]
    return {
        "feed_recent": feed_recent,
        "feed_total": len(feed_recent),
        "active_sources": len({threat["source"] for threat in threats}),
    }


def get_reports_context() -> Dict[str, object]:
    threats = get_filtered_threats()
    grouped: Dict[str, List[Dict[str, str | int]]] = {}
    for threat in threats:
        grouped.setdefault(str(threat["threat"]), []).append(threat)

    report_sections = []
    for threat_name, items in sorted(grouped.items(), key=lambda pair: len(pair[1]), reverse=True):
        sorted_items = sorted(items, key=lambda item: int(item["score"]), reverse=True)
        avg_score = round(sum(int(item["score"]) for item in items) / len(items))
        risks = Counter(str(item["risk"]) for item in items)
        types = Counter(str(item["type"]) for item in items)
        sources = Counter(str(item["source"]) for item in items)
        latest = max(items, key=lambda item: str(item["created_at"]))

        report_sections.append(
            {
                "name": threat_name,
                "count": len(items),
                "avg_score": avg_score,
                "dominant_risk": max(risks, key=risks.get),
                "top_type": max(types, key=types.get),
                "top_source": max(sources, key=sources.get),
                "latest_seen": latest["created_display"],
                "summary": _build_report_summary(threat_name, items, avg_score),
                "iocs": sorted_items[:5],
            }
        )

    newest = sorted(threats, key=lambda item: str(item["created_at"]), reverse=True)[:8]
    return {
        "report_sections": report_sections,
        "new_additions": newest,
        "report_total": len(report_sections),
        "ioc_total": len(threats),
    }


def get_high_risk_alerts(status: str = "All") -> List[Dict[str, str | int]]:
    alerts = [threat for threat in get_filtered_threats() if threat["risk"] == "HIGH"]
    if status != "All":
        alerts = [alert for alert in alerts if alert["status"] == status]
    return alerts


def get_threat_by_id(threat_id: int) -> Optional[Dict[str, object]]:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, ioc, type, threat, confidence, score, status, source, created_at, updated_at
            FROM threats
            WHERE id = ?
            """,
            (threat_id,),
        ).fetchone()
    if row is None:
        return None

    threat = _format_threat(row)
    threat["intel"] = _build_threat_intel(threat)
    threat["related"] = _find_related_threats(threat)
    return threat


def _build_weekly_summary(threats: List[Dict[str, str | int]]) -> List[Dict[str, str]]:
    sorted_threats = sorted(threats, key=lambda threat: int(threat["score"]), reverse=True)[:4]
    summary = []
    for threat in sorted_threats:
        summary.append(
            {
                "title": threat["headline"],
                "body": f"{threat['summary']} Analyst queue status is {threat['status']} with confidence rated {threat['confidence']}.",
            }
        )
    return summary


def _build_breaking_news(threats: List[Dict[str, str | int]]) -> List[Dict[str, str]]:
    newest = sorted(threats, key=lambda threat: str(threat["created_at"]), reverse=True)[:4]
    news = []
    for threat in newest:
        news.append(
            {
                "title": f"{threat['threat']} update",
                "body": f"{threat['ioc']} was ingested from {threat['source']} with a {threat['risk']} risk score of {threat['score']}.",
            }
        )
    return news


def _build_trendy_words(threats: List[Dict[str, str | int]]) -> List[Dict[str, object]]:
    counts = Counter(str(threat["threat"]) for threat in threats)
    latest_seen = {}
    reliability = {}
    linked_id = {}
    for threat in threats:
        label = str(threat["threat"])
        latest_seen[label] = threat["created_display"]
        linked_id[label] = threat["id"]
        reliability[label] = max(reliability.get(label, 0), int(threat["score"]))

    rows = []
    for label, count in counts.most_common(6):
        rows.append(
            {
                "label": label,
                "count": count,
                "reliability": min(100, reliability[label]),
                "found": latest_seen[label],
                "threat_id": linked_id[label],
            }
        )
    return rows


def _build_threat_summary(ioc: str, ioc_type: str, threat_type: str, severity: str) -> str:
    return (
        f"{ioc_type} indicator {ioc} has been correlated with {threat_type.lower()} behavior. "
        f"The platform currently classifies this event as {severity.lower()} severity based on IOC profile, naming pattern, and feed context."
    )


def _map_tactic(threat_type: str) -> str:
    mapping = {
        "Phishing": "Initial Access",
        "Credential Harvesting": "Credential Access",
        "Command and Control": "Command and Control",
        "Botnet": "Command and Control",
        "Drive-by Download": "Execution",
        "Ransomware": "Impact",
        "Loader": "Execution",
        "Backdoor": "Persistence",
        "Brute Force": "Credential Access",
        "Malware Delivery": "Initial Access",
        "Malware Beacon": "Command and Control",
        "Suspicious Scanner": "Reconnaissance",
        "Typosquatting": "Resource Development",
        "Exploit Kit": "Execution",
        "Trojan": "Execution",
    }
    return mapping.get(threat_type, "Discovery")


def _priority_rank(score: int, status: str) -> str:
    if score >= 90:
        return "P1"
    if score >= 80 and status != "Closed":
        return "P2"
    if score >= 65:
        return "P3"
    return "P4"


def _build_threat_intel(threat: Dict[str, str | int]) -> Dict[str, object]:
    ioc = str(threat["ioc"])
    return {
        "overview": threat["summary"],
        "attack_story": (
            f"Analysts observed {ioc} entering the environment through {threat['source']}. "
            f"Behavioral scoring suggests {str(threat['threat']).lower()} activity aligned to {threat['tactic']}."
        ),
        "recommended_actions": [
            f"Block or sinkhole {ioc} across perimeter controls.",
            "Correlate historical authentication and DNS/proxy logs for related activity.",
            f"Escalate to SOC workflow as {threat['priority_rank']} until analyst validation is complete.",
        ],
        "kill_chain": [
            {"label": "Recon", "active": str(threat["threat"]) in ["Suspicious Scanner", "Typosquatting"]},
            {"label": "Delivery", "active": str(threat["type"]) in ["Domain", "URL"]},
            {"label": "Execution", "active": str(threat["threat"]) in ["Drive-by Download", "Loader", "Exploit Kit", "Trojan"]},
            {"label": "C2", "active": str(threat["threat"]) in ["Botnet", "Command and Control", "Malware Beacon", "Backdoor"]},
            {"label": "Impact", "active": str(threat["threat"]) == "Ransomware"},
        ],
        "telemetry": [
            {"label": "Risk Score", "value": str(threat["score"])},
            {"label": "Confidence", "value": str(threat["confidence"])},
            {"label": "Tactic", "value": str(threat["tactic"])},
            {"label": "Priority", "value": str(threat["priority_rank"])},
        ],
    }


def _find_related_threats(base: Dict[str, str | int]) -> List[Dict[str, str | int]]:
    threats = get_filtered_threats()
    related = [
        threat
        for threat in threats
        if threat["id"] != base["id"]
        and (
            threat["type"] == base["type"]
            or threat["threat"] == base["threat"]
            or threat["source"] == base["source"]
        )
    ]
    return sorted(related, key=lambda threat: int(threat["score"]), reverse=True)[:5]
