from flask import Flask, jsonify, render_template, request
import sqlite3
import json

app = Flask(__name__)

DATABASE = "/data/events.db"


# ─────────────────────────────────────────────────────────────────────────────
# Security Headers
# ─────────────────────────────────────────────────────────────────────────────

@app.after_request
def set_security_headers(response):
    """Apply security headers to every response."""
    # TODO(security): Tighten CSP script-src to use nonces in production.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "frame-ancestors 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"]          = "no-store"
    return response


# ─────────────────────────────────────────────────────────────────────────────
# DB helpers — parameterized queries only (no SQL injection)
# ─────────────────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def _table_exists(conn, table: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


# ─────────────────────────────────────────────────────────────────────────────
# Main dashboard page
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    conn = get_db()
    try:
        events = []
        total_events = high_risk = auto_count = human_count = correlated_count = 0
        node_status_records = []

        if _table_exists(conn, "events"):
            events = conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT 20"
            ).fetchall()
            total_events = conn.execute(
                "SELECT COUNT(*) as count FROM events"
            ).fetchone()["count"]
            high_risk = conn.execute("""
                SELECT COUNT(*) as count FROM events
                WHERE bucket = 'quarantine'
                   OR (bucket IS NULL AND risk_score >= 100)
            """).fetchone()["count"]
            auto_count = conn.execute(
                "SELECT COUNT(*) as count FROM events WHERE bucket = 'auto'"
            ).fetchone()["count"]
            human_count = conn.execute(
                "SELECT COUNT(*) as count FROM events WHERE bucket = 'human'"
            ).fetchone()["count"]
            correlated_count = conn.execute(
                "SELECT COUNT(*) as count FROM events WHERE correlated = 1"
            ).fetchone()["count"]

        if _table_exists(conn, "node_status"):
            node_status_records = conn.execute(
                "SELECT * FROM node_status ORDER BY node ASC"
            ).fetchall()

    finally:
        conn.close()

    return render_template(
        "index.html",
        events=events,
        total_events=total_events,
        high_risk=high_risk,
        auto_count=auto_count,
        human_count=human_count,
        correlated_count=correlated_count,
        nodes=node_status_records,
    )


# ─────────────────────────────────────────────────────────────────────────────
# API: Nodes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/nodes")
def api_nodes():
    conn = get_db()
    try:
        if not _table_exists(conn, "node_status"):
            return jsonify([])
        nodes = conn.execute(
            "SELECT * FROM node_status ORDER BY node ASC"
        ).fetchall()
        return jsonify([dict(r) for r in nodes])
    finally:
        conn.close()


@app.route("/api/nodes/identity")
def api_node_identity():
    """Per-node identity records: machine_id, trust status, first/last seen."""
    conn = get_db()
    try:
        if not _table_exists(conn, "node_identity"):
            return jsonify([])
        rows = conn.execute(
            "SELECT * FROM node_identity ORDER BY node ASC"
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/nodes/security")
def api_node_security():
    """Per-node security summary: replay count, flood count, heartbeat, integrity."""
    conn = get_db()
    try:
        if not _table_exists(conn, "node_status"):
            return jsonify([])

        # Build joined summary — all parameterized
        rows = conn.execute("""
            SELECT
                ns.node,
                ns.status,
                ns.risk_score,
                ns.last_updated,
                COALESCE(ni.machine_id, '') as machine_id,
                COALESCE(ni.trust_status, 'UNKNOWN') as trust_status,
                COALESCE(ni.first_seen, '') as first_seen,
                COALESCE((
                    SELECT COUNT(*) FROM replay_log WHERE node = ns.node
                ), 0) as replay_count,
                COALESCE((
                    SELECT COUNT(*) FROM security_alerts
                    WHERE node_id = ns.node AND threat_type = 'FLOOD_ATTACK'
                ), 0) as flood_count,
                COALESCE((
                    SELECT COUNT(*) FROM security_alerts
                    WHERE node_id = ns.node AND threat_type = 'CONFIG_TAMPER'
                ), 0) as config_tamper_count,
                COALESCE((
                    SELECT COUNT(*) FROM security_alerts
                    WHERE node_id = ns.node AND threat_type = 'LATERAL_MOVEMENT'
                ), 0) as lateral_movement_count,
                COALESCE((
                    SELECT COUNT(*) FROM security_alerts
                    WHERE node_id = ns.node AND threat_type = 'SILENT_NODE'
                ), 0) as silent_count
            FROM node_status ns
            LEFT JOIN node_identity ni ON ni.node = ns.node
            ORDER BY ns.node ASC
        """).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# API: Security Alerts
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/alerts")
def api_alerts():
    """
    Paginated security alerts.
    Query params: limit (int), severity (str), node_id (str), threat_type (str)
    All user inputs are passed as SQL parameters — no interpolation.
    """
    # Validate and sanitise query params
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
    except (ValueError, TypeError):
        limit = 50

    severity    = request.args.get("severity", "").strip() or None
    node_id     = request.args.get("node_id", "").strip() or None
    threat_type = request.args.get("threat_type", "").strip() or None

    # Allowlist severity values to prevent unexpected filter bypass
    allowed_severities = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    if severity and severity.upper() not in allowed_severities:
        severity = None
    else:
        severity = severity.upper() if severity else None

    conn = get_db()
    try:
        if not _table_exists(conn, "security_alerts"):
            return jsonify([])

        conditions = []
        params     = []
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if node_id:
            conditions.append("node_id = ?")
            params.append(node_id)
        if threat_type:
            conditions.append("threat_type = ?")
            params.append(threat_type)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)

        rows = conn.execute(
            f"SELECT * FROM security_alerts {where} ORDER BY timestamp DESC LIMIT ?",
            params,
        ).fetchall()

        result = []
        for r in rows:
            row = dict(r)
            # Parse evidence JSON safely
            try:
                row["evidence"] = json.loads(row.get("evidence", "{}"))
            except (json.JSONDecodeError, TypeError):
                row["evidence"] = {}
            result.append(row)

        return jsonify(result)
    finally:
        conn.close()


@app.route("/api/alerts/stats")
def api_alert_stats():
    """Aggregate threat statistics for dashboard charts."""
    conn = get_db()
    try:
        if not _table_exists(conn, "security_alerts"):
            return jsonify({
                "total": 0, "by_type": {}, "by_severity": {},
                "recent_24h": 0
            })

        rows = conn.execute("""
            SELECT threat_type, severity, COUNT(*) as count
            FROM security_alerts
            GROUP BY threat_type, severity
        """).fetchall()

        by_type     = {}
        by_severity = {}
        for row in rows:
            tt  = row["threat_type"]
            sev = row["severity"]
            cnt = row["count"]
            by_type[tt]      = by_type.get(tt, 0) + cnt
            by_severity[sev] = by_severity.get(sev, 0) + cnt

        total = conn.execute(
            "SELECT COUNT(*) as c FROM security_alerts"
        ).fetchone()["c"]

        recent_24h = conn.execute("""
            SELECT COUNT(*) as c FROM security_alerts
            WHERE timestamp >= datetime('now', '-24 hours')
        """).fetchone()["c"]

        replay_total = 0
        if _table_exists(conn, "replay_log"):
            replay_total = conn.execute(
                "SELECT COUNT(*) as c FROM replay_log"
            ).fetchone()["c"]

        return jsonify({
            "total":        total,
            "by_type":      by_type,
            "by_severity":  by_severity,
            "recent_24h":   recent_24h,
            "replay_total": replay_total,
        })
    finally:
        conn.close()


if __name__ == "__main__":
    # TODO(security): In production, run behind a TLS-terminating reverse proxy.
    # Do NOT expose 0.0.0.0 externally without network-level access control.
    app.run(host="0.0.0.0", port=5000)  # nosemgrep: python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host — intentional: container bound to internal Docker network only
