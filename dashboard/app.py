from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

DATABASE = "/data/events.db"

def get_db_connection():

    conn = sqlite3.connect(DATABASE)

    conn.row_factory = sqlite3.Row

    return conn

@app.route("/")

def index():

    conn = get_db_connection()

    # recent events
    events = conn.execute("""

        SELECT *
        FROM events
        ORDER BY id DESC
        LIMIT 20

    """).fetchall()

    # total events
    total_events = conn.execute("""

        SELECT COUNT(*) as count
        FROM events

    """).fetchone()["count"]

    # high-risk events
    high_risk = conn.execute("""

        SELECT COUNT(*) as count
        FROM events
        WHERE risk_score >= 100

    """).fetchone()["count"]

    conn.close()

    return render_template(
        "index.html",
        events=events,
        total_events=total_events,
        high_risk=high_risk
    )

if __name__ == "__main__":

    app.run(host="0.0.0.0", port=5000)
