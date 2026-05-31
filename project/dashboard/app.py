"""
Always-On Security — Dashboard
Layer 5: Web-based monitoring interface

Reads from shared SQLite database and renders
security events, job history, and node status.
"""

from flask import Flask, render_template, jsonify
import sqlite3

app = Flask(__name__)

DATABASE = "/data/events.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    conn = get_db()

    # Recent security events (last 30)
    events = conn.execute("""
        SELECT * FROM events
        ORDER BY id DESC
        LIMIT 30
    """).fetchall()

    # Total events
    total_events = conn.execute(
        "SELECT COUNT(*) as count FROM events"
    ).fetchone()["count"]

    # Suspicious events
    suspicious_count = conn.execute(
        "SELECT COUNT(*) as count FROM events WHERE event_type = 'SUSPICIOUS_ACTIVITY'"
    ).fetchone()["count"]

    # High-risk events (risk >= 100)
    high_risk = conn.execute(
        "SELECT COUNT(*) as count FROM events WHERE risk_score >= 100"
    ).fetchone()["count"]

    # Unresponsive events
    unresponsive_count = conn.execute(
        "SELECT COUNT(*) as count FROM events WHERE event_type = 'NODE_UNRESPONSIVE'"
    ).fetchone()["count"]

    # Node status
    nodes = []
    try:
        nodes = conn.execute(
            "SELECT * FROM node_status ORDER BY node"
        ).fetchall()
    except Exception:
        pass  # Table may not exist yet

    # Recent jobs (last 20)
    jobs = []
    try:
        jobs = conn.execute("""
            SELECT * FROM jobs
            ORDER BY id DESC
            LIMIT 20
        """).fetchall()
    except Exception:
        pass  # Table may not exist yet

    conn.close()

    return render_template(
        "index.html",
        events=events,
        total_events=total_events,
        suspicious_count=suspicious_count,
        high_risk=high_risk,
        unresponsive_count=unresponsive_count,
        nodes=nodes,
        jobs=jobs,
    )


@app.route("/api/stats")
def api_stats():
    """JSON endpoint for AJAX polling."""
    conn = get_db()

    stats = {
        "total_events": conn.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0],
        "suspicious": conn.execute(
            "SELECT COUNT(*) FROM events WHERE event_type = 'SUSPICIOUS_ACTIVITY'"
        ).fetchone()[0],
        "high_risk": conn.execute(
            "SELECT COUNT(*) FROM events WHERE risk_score >= 100"
        ).fetchone()[0],
    }

    conn.close()
    return jsonify(stats)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
