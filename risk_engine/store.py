import sqlite3
import json
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

DB_PATH = "/data/events.db"


class Store:
    def __init__(self):
        self.conn = sqlite3.connect(
            DB_PATH,
            check_same_thread=False,
        )

        self.conn.row_factory = sqlite3.Row

        self.conn.execute("PRAGMA journal_mode=WAL")

        self._init_schema()

    # ==================================
    # SCHEMA
    # ==================================

    def _init_schema(self):

        c = self.conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT NOT NULL,

                node TEXT NOT NULL,

                cpu_usage REAL,
                memory_usage REAL,
                process_count INTEGER,

                failed_login_count INTEGER DEFAULT 0,
                privilege_escalation_attempts INTEGER DEFAULT 0,

                event_type TEXT,
                reasons TEXT,

                risk_score REAL,

                weighted_score REAL,

                bucket TEXT,

                correlated INTEGER DEFAULT 0,

                matched_rules TEXT
            )
        """)

        # --------------------------
        # Migration Support
        # --------------------------

        for col, defn in [
            ("weighted_score", "REAL"),
            ("bucket", "TEXT"),
            (
                "correlated",
                "INTEGER DEFAULT 0",
            ),
            (
                "matched_rules",
                "TEXT",
            ),
            (
                "failed_login_count",
                "INTEGER DEFAULT 0",
            ),
            (
                "privilege_escalation_attempts",
                "INTEGER DEFAULT 0",
            ),
        ]:

            try:

                c.execute(f"ALTER TABLE events " f"ADD COLUMN {col} {defn}")

            except sqlite3.OperationalError:
                pass

        # --------------------------
        # Node Scores
        # --------------------------

        c.execute("""
            CREATE TABLE IF NOT EXISTS node_scores (
                node TEXT PRIMARY KEY,

                cumulative_score REAL NOT NULL DEFAULT 0,

                updated_at TEXT NOT NULL
            )
        """)

        # --------------------------
        # Engine Offset
        # --------------------------

        c.execute("""
            CREATE TABLE IF NOT EXISTS engine_offset (
                id INTEGER PRIMARY KEY
                CHECK (id = 1),

                last_committed INTEGER NOT NULL
                DEFAULT 0
            )
        """)

        # --------------------------
        # Node Status
        # --------------------------

        c.execute("""
            CREATE TABLE IF NOT EXISTS node_status (
                node TEXT PRIMARY KEY,

                status TEXT NOT NULL,

                risk_score REAL NOT NULL,

                last_updated TEXT NOT NULL
            )
        """)

        c.execute("""
            INSERT OR IGNORE INTO
            engine_offset (
                id,
                last_committed
            )
            VALUES (
                1,
                0
            )
        """)

        self.conn.commit()

        log.info("Schema initialised")

    # ==================================
    # OFFSETS
    # ==================================

    def last_committed_offset(self):

        row = self.conn.execute("""
            SELECT last_committed
            FROM engine_offset
            WHERE id=1
        """).fetchone()

        return row["last_committed"] if row else 0

    # ==================================
    # NODE SCORE
    # ==================================

    def get_node_score(self, node):

        row = self.conn.execute(
            """
            SELECT cumulative_score
            FROM node_scores
            WHERE node=?
        """,
            (node,),
        ).fetchone()

        return float(row["cumulative_score"]) if row else 0.0

    # ==================================
    # INCIDENT COUNTS
    # ==================================

    def get_incident_count_7d(self, node):

        row = self.conn.execute(
            """
            SELECT COUNT(*) as cnt
            FROM events

            WHERE node=?

            AND bucket IN (
                'auto',
                'human',
                'quarantine'
            )

            AND timestamp >=
                datetime(
                    'now',
                    '-7 days'
                )
        """,
            (node,),
        ).fetchone()

        return int(row["cnt"]) if row else 0

    # ==================================
    # WRITE EVENT
    # ==================================

    def write_event(
        self,
        event,
        decision,
    ):

        ts = event.get("_received_at", datetime.now(timezone.utc).isoformat())

        c = self.conn.cursor()

        c.execute(
            """
            INSERT INTO events (

                timestamp,

                node,

                cpu_usage,
                memory_usage,
                process_count,

                failed_login_count,
                privilege_escalation_attempts,

                event_type,

                reasons,

                risk_score,

                weighted_score,

                bucket,

                correlated,

                matched_rules

            )
            VALUES (
                ?, ?, ?, ?, ?,
                ?, ?,
                ?, ?,
                ?, ?,
                ?, ?, ?
            )
        """,
            (
                ts,
                decision.node,
                event.get("cpu_usage"),
                event.get("memory_usage"),
                event.get("process_count"),
                event.get(
                    "failed_login_count",
                    0,
                ),
                event.get(
                    "privilege_escalation_attempts",
                    0,
                ),
                event.get(
                    "event_type",
                    "NORMAL",
                ),
                json.dumps(
                    event.get(
                        "reasons",
                        [],
                    )
                ),
                float(decision.cumulative_score),
                float(decision.event_score),
                decision.bucket,
                1 if decision.correlated else 0,
                json.dumps([r[0] for r in decision.matched_rules]),
            ),
        )

        # --------------------------
        # Update Score Table
        # --------------------------

        c.execute(
            """
            INSERT INTO node_scores (
                node,
                cumulative_score,
                updated_at
            )
            VALUES (?, ?, ?)

            ON CONFLICT(node)
            DO UPDATE SET

                cumulative_score =
                    excluded.cumulative_score,

                updated_at =
                    excluded.updated_at
        """,
            (
                decision.node,
                decision.cumulative_score,
                ts,
            ),
        )

        # --------------------------
        # Commit Offset
        # --------------------------

        c.execute(
            """
            UPDATE engine_offset
            SET last_committed=?
            WHERE id=1
        """,
            (event["_offset"],),
        )

        self.conn.commit()

    # ==================================
    # NODE STATUS
    # ==================================

    def update_node_status(
        self,
        node,
        status,
        risk_score,
    ):

        ts = datetime.now(timezone.utc).isoformat()

        c = self.conn.cursor()

        c.execute(
            """
            INSERT INTO node_status (
                node,
                status,
                risk_score,
                last_updated
            )
            VALUES (?, ?, ?, ?)

            ON CONFLICT(node)
            DO UPDATE SET

                status =
                    excluded.status,

                risk_score =
                    excluded.risk_score,

                last_updated =
                    excluded.last_updated
        """,
            (
                node,
                status,
                risk_score,
                ts,
            ),
        )

        self.conn.commit()

    # ==================================
    # HEARTBEAT EVENTS
    # ==================================

    def write_heartbeat_event(
        self,
        node,
        delta_seconds,
    ):

        ts = datetime.now(timezone.utc).isoformat()

        c = self.conn.cursor()

        c.execute(
            """
            INSERT INTO events (

                timestamp,

                node,

                event_type,

                reasons,

                risk_score

            )
            VALUES (
                ?, ?, ?, ?, ?
            )
        """,
            (
                ts,
                node,
                "NODE_UNRESPONSIVE",
                json.dumps([f"Node silent for " f"{delta_seconds:.0f}s"]),
                100.0,
            ),
        )

        c.execute(
            """
            INSERT INTO node_status (

                node,

                status,

                risk_score,

                last_updated

            )
            VALUES (
                ?, ?, ?, ?
            )

            ON CONFLICT(node)
            DO UPDATE SET

                status =
                    excluded.status,

                risk_score =
                    excluded.risk_score,

                last_updated =
                    excluded.last_updated
        """,
            (
                node,
                "unresponsive",
                100.0,
                ts,
            ),
        )

        self.conn.commit()

    # ==================================
    # WARM RESTART
    # ==================================

    def warm_restart_events(
        self,
        window_seconds,
    ):

        rows = self.conn.execute(
            """
            SELECT

                node,

                matched_rules,

                timestamp

            FROM events

            WHERE matched_rules
                IS NOT NULL

            AND timestamp >=
                datetime(
                    'now',
                    ?
                )

            ORDER BY id ASC
        """,
            (f"-{window_seconds} seconds",),
        ).fetchall()

        return [dict(r) for r in rows]
