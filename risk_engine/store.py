import sqlite3
import json
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

DB_PATH = "/data/events.db"


class Store:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self):
        c = self.conn.cursor()

        # ── Original tables ──────────────────────────────────────────
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

        # Migration support for older databases
        for col, defn in [
            ("weighted_score",                "REAL"),
            ("bucket",                        "TEXT"),
            ("correlated",                    "INTEGER DEFAULT 0"),
            ("matched_rules",                 "TEXT"),
            ("failed_login_count",            "INTEGER DEFAULT 0"),
            ("privilege_escalation_attempts",  "INTEGER DEFAULT 0"),
            ("file_path",                     "TEXT"),
            ("fim_event_type",                "TEXT"),
            ("sha256",                        "TEXT"),
            ("file_size",                     "INTEGER"),
            ("permissions",                   "TEXT"),
        ]:
            try:
                c.execute(f"ALTER TABLE events ADD COLUMN {col} {defn}")
            except sqlite3.OperationalError:
                pass

        c.execute("""
            CREATE TABLE IF NOT EXISTS node_scores (
                node TEXT PRIMARY KEY,
                cumulative_score REAL NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS engine_offset (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_committed INTEGER NOT NULL DEFAULT 0
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS node_status (
                node TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                risk_score REAL NOT NULL,
                last_updated TEXT NOT NULL
            )
        """)

        try:
            c.execute("ALTER TABLE node_status ADD COLUMN isolated_ip TEXT DEFAULT NULL")
        except sqlite3.OperationalError:
            pass

        c.execute("""
            INSERT OR IGNORE INTO engine_offset (id, last_committed)
            VALUES (1, 0)
        """)

        # ── New security tables ──────────────────────────────────────

        c.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                node_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                recommended_action TEXT NOT NULL
            )
        """)
        # Index for fast dashboard queries
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_node
            ON security_alerts (node_id, timestamp DESC)
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_severity
            ON security_alerts (severity, timestamp DESC)
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS node_identity (
                node TEXT PRIMARY KEY,
                machine_id TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                trust_status TEXT NOT NULL
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS replay_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node TEXT NOT NULL,
                msg_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                detected_at TEXT NOT NULL
            )
        """)

        # ── REC-09: Forensic snapshot table ──────────────────────────
        # Stores pre-quarantine evidence captured before a container is stopped.
        # NIST SP 800-234: IR-4 (Incident Handling), IR-5 (Incident Monitoring)
        c.execute("""
            CREATE TABLE IF NOT EXISTS forensic_snapshots (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                captured_at  TEXT NOT NULL,
                node         TEXT NOT NULL,
                trigger      TEXT NOT NULL,
                risk_score   REAL NOT NULL,
                processes    TEXT,
                network_conns TEXT,
                container_state TEXT,
                recent_alerts TEXT,
                recent_events TEXT,
                artifact_path TEXT
            )
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_forensics_node
            ON forensic_snapshots (node, captured_at DESC)
        """)

        self.conn.commit()
        log.info("Schema initialised (events + security + forensic tables)")

    # ── Original methods ─────────────────────────────────────────────

    def last_committed_offset(self) -> int:
        row = self.conn.execute(
            "SELECT last_committed FROM engine_offset WHERE id=1"
        ).fetchone()
        return row["last_committed"] if row else 0

    def get_node_score(self, node: str) -> float:
        row = self.conn.execute(
            "SELECT cumulative_score FROM node_scores WHERE node=?", (node,)
        ).fetchone()
        return float(row["cumulative_score"]) if row else 0.0

    def get_incident_count_7d(self, node: str) -> int:
        row = self.conn.execute("""
            SELECT COUNT(*) as cnt FROM events
            WHERE node=?
              AND bucket IN ('auto', 'human', 'quarantine')
              AND timestamp >= datetime('now', '-7 days')
        """, (node,)).fetchone()
        return int(row["cnt"]) if row else 0

    def get_node_status(self, node):
        row = self.conn.execute(
            "SELECT status FROM node_status WHERE node=?", (node,)
        ).fetchone()
        return row["status"] if row else "idle"

    def write_event(self, event: dict, decision) -> None:
        ts = event.get("_received_at", datetime.now(timezone.utc).isoformat())
        fim = event.get("fim_details") or {}
        c = self.conn.cursor()
        c.execute("""
            INSERT INTO events (
                timestamp, node, cpu_usage, memory_usage, process_count,
                failed_login_count, privilege_escalation_attempts,
                event_type, reasons, risk_score,
                weighted_score, bucket, correlated, matched_rules,
                file_path, fim_event_type, sha256, file_size, permissions
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ts,
            decision.node,
            event.get("cpu_usage"),
            event.get("memory_usage"),
            event.get("process_count"),
            event.get("failed_login_count", 0),
            event.get("privilege_escalation_attempts", 0),
            event.get("event_type", "NORMAL"),
            json.dumps(event.get("reasons", [])),
            float(decision.cumulative_score),
            float(decision.event_score),
            decision.bucket,
            1 if decision.correlated else 0,
            json.dumps([r[0] for r in decision.matched_rules]),
            fim.get("file_path"),
            fim.get("fim_event_type"),
            fim.get("current_state", {}).get("sha256") if fim.get("current_state") else None,
            fim.get("current_state", {}).get("file_size") if fim.get("current_state") else None,
            fim.get("current_state", {}).get("permissions") if fim.get("current_state") else None,
        ))
        c.execute("""
            INSERT INTO node_scores (node, cumulative_score, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(node) DO UPDATE SET
                cumulative_score = excluded.cumulative_score,
                updated_at       = excluded.updated_at
        """, (decision.node, decision.cumulative_score, ts))
        c.execute(
            "UPDATE engine_offset SET last_committed=? WHERE id=1",
            (event["_offset"],),
        )
        self.conn.commit()

    def update_node_status(self, node: str, status: str, risk_score: float, isolated_ip: str = None) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        c = self.conn.cursor()
        
        # If isolated_ip is provided, we update it; if not, we leave it as is or insert NULL if new
        if isolated_ip is not None:
            c.execute("""
                INSERT INTO node_status (node, status, risk_score, last_updated, isolated_ip)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(node) DO UPDATE SET
                    status = excluded.status,
                    risk_score = excluded.risk_score,
                    last_updated = excluded.last_updated,
                    isolated_ip = excluded.isolated_ip
            """, (node, status, risk_score, ts, isolated_ip))
        else:
            c.execute("""
                INSERT INTO node_status (node, status, risk_score, last_updated)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(node) DO UPDATE SET
                    status = excluded.status,
                    risk_score = excluded.risk_score,
                    last_updated = excluded.last_updated
            """, (node, status, risk_score, ts))
        self.conn.commit()

    def get_isolated_ip(self, node: str) -> str:
        row = self.conn.execute(
            "SELECT isolated_ip FROM node_status WHERE node=?", (node,)
        ).fetchone()
        return row["isolated_ip"] if row else None

    def set_isolated_ip(self, node: str, ip: str) -> None:
        self.conn.execute(
            "UPDATE node_status SET isolated_ip=? WHERE node=?", (ip, node)
        )
        self.conn.commit()

    def reset_node_score(self, node: str) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        self.conn.execute("""
            INSERT INTO node_scores (node, cumulative_score, updated_at)
            VALUES (?, 0.0, ?)
            ON CONFLICT(node) DO UPDATE SET
                cumulative_score = 0.0,
                updated_at = excluded.updated_at
        """, (node, ts))
        self.conn.commit()

    def reset_all_tables(self) -> None:
        c = self.conn.cursor()
        c.execute("BEGIN TRANSACTION")
        tables = [
            "events", "node_scores", "node_status", "security_alerts",
            "node_identity", "replay_log", "forensic_snapshots"
        ]
        for table in tables:
            try:
                c.execute(f"DELETE FROM {table}")
            except sqlite3.OperationalError:
                pass
        
        c.execute("UPDATE engine_offset SET last_committed = 0 WHERE id = 1")
        self.conn.commit()

    def write_heartbeat_event(self, node: str, delta_seconds: float) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        c = self.conn.cursor()
        c.execute("""
            INSERT INTO events (
                timestamp, node, event_type, reasons, risk_score
            ) VALUES (?, ?, ?, ?, ?)
        """, (
            ts, node, "NODE_UNRESPONSIVE",
            json.dumps([f"Node silent for {delta_seconds:.0f}s"]), 100.0
        ))
        c.execute("""
            INSERT INTO node_status (node, status, risk_score, last_updated)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(node) DO UPDATE SET
                status = excluded.status,
                risk_score = excluded.risk_score,
                last_updated = excluded.last_updated
        """, (node, "unresponsive", 100.0, ts))
        self.conn.commit()

    def warm_restart_events(self, window_seconds: int) -> list:
        rows = self.conn.execute("""
            SELECT node, matched_rules, timestamp FROM events
            WHERE matched_rules IS NOT NULL
              AND timestamp >= datetime('now', ?)
            ORDER BY id ASC
        """, (f"-{window_seconds} seconds",)).fetchall()
        return [dict(r) for r in rows]

    # ── Security alert methods ───────────────────────────────────────

    def write_alert(self, alert) -> None:
        """Persist a SecurityAlert dataclass to the security_alerts table."""
        c = self.conn.cursor()
        c.execute("""
            INSERT OR IGNORE INTO security_alerts (
                alert_id, timestamp, node_id, severity,
                threat_type, description, evidence, recommended_action
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.alert_id,
            alert.timestamp,
            alert.node_id,
            alert.severity,
            alert.threat_type,
            alert.description,
            json.dumps(alert.evidence),
            alert.recommended_action,
        ))
        self.conn.commit()

    def get_alerts(
        self,
        limit: int = 50,
        severity: str = None,
        node_id: str = None,
        threat_type: str = None,
    ) -> list:
        """Paginated security alert query with optional filters. Parameterized — no SQL injection."""
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

        rows = self.conn.execute(
            f"SELECT * FROM security_alerts {where} ORDER BY timestamp DESC LIMIT ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]

    def get_threat_stats(self) -> dict:
        """Return aggregate counts for the dashboard."""
        rows = self.conn.execute("""
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
            by_type[tt]     = by_type.get(tt, 0) + cnt
            by_severity[sev] = by_severity.get(sev, 0) + cnt

        total = self.conn.execute(
            "SELECT COUNT(*) as c FROM security_alerts"
        ).fetchone()["c"]

        return {
            "total":       total,
            "by_type":     by_type,
            "by_severity": by_severity,
        }

    # ── Node identity methods ────────────────────────────────────────

    def upsert_node_identity(
        self,
        node: str,
        machine_id: str,
        trust_status: str = "TRUSTED",
    ) -> None:
        ts  = datetime.now(timezone.utc).isoformat()
        c   = self.conn.cursor()
        # Use INSERT ... ON CONFLICT to preserve first_seen
        c.execute("""
            INSERT INTO node_identity (node, machine_id, first_seen, last_seen, trust_status)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(node) DO UPDATE SET
                machine_id   = excluded.machine_id,
                last_seen    = excluded.last_seen,
                trust_status = excluded.trust_status
        """, (node, machine_id, ts, ts, trust_status))
        self.conn.commit()

    def get_node_identity(self, node: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM node_identity WHERE node=?", (node,)
        ).fetchone()
        return dict(row) if row else None

    def get_all_node_identities(self) -> list:
        rows = self.conn.execute(
            "SELECT * FROM node_identity ORDER BY node ASC"
        ).fetchall()
        return [dict(r) for r in rows]

    def log_replay(self, node: str, msg_id: str, seq: int) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        self.conn.execute("""
            INSERT INTO replay_log (node, msg_id, seq, detected_at)
            VALUES (?, ?, ?, ?)
        """, (node, msg_id, seq, ts))
        self.conn.commit()

    def get_replay_count(self, node: str = None) -> int:
        if node:
            row = self.conn.execute(
                "SELECT COUNT(*) as c FROM replay_log WHERE node=?", (node,)
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT COUNT(*) as c FROM replay_log"
            ).fetchone()
        return row["c"] if row else 0

    def get_node_security_summary(self) -> list:
        """Per-node security summary for dashboard."""
        rows = self.conn.execute("""
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
                    WHERE node_id = ns.node
                    AND threat_type IN ('CONFIG_DRIFT','POLICY_TAMPER','ALLOWLIST_TAMPER')
                ), 0) as config_tamper_count,
                COALESCE((
                    SELECT COUNT(*) FROM security_alerts
                    WHERE node_id = ns.node AND threat_type = 'LATERAL_MOVEMENT'
                ), 0) as lateral_movement_count,
                COALESCE((
                    SELECT COUNT(*) FROM security_alerts
                    WHERE node_id = ns.node
                    AND threat_type IN ('IMAGE_MISMATCH','UNAPPROVED_IMAGE','IMAGE_DRIFT')
                ), 0) as image_alert_count,
                COALESCE((
                    SELECT COUNT(*) FROM security_alerts
                    WHERE node_id = ns.node AND threat_type = 'RUNTIME_DRIFT'
                ), 0) as runtime_drift_count,
                COALESCE((
                    SELECT COUNT(*) FROM security_alerts
                    WHERE node_id = ns.node
                    AND threat_type IN ('FALCO_ALERT','REVERSE_SHELL','PRIV_ESC_ATTEMPT','CONTAINER_ESCAPE_ATTEMPT')
                ), 0) as falco_alert_count
            FROM node_status ns
            LEFT JOIN node_identity ni ON ni.node = ns.node
            ORDER BY ns.node ASC
        """).fetchall()
        return [dict(r) for r in rows]

    # ── REC-09: Forensic snapshot methods ───────────────────────────

    def write_forensic_snapshot(
        self,
        node: str,
        trigger: str,
        risk_score: float,
        processes: list,
        network_conns: list,
        container_state: dict,
        recent_alerts: list,
        recent_events: list,
        artifact_path: str | None = None,
    ) -> int:
        """
        Persist a pre-quarantine forensic snapshot.
        Returns the row ID of the inserted record.
        NIST IR-4 / IR-5 — evidence preservation before remediation.
        """
        ts = datetime.now(timezone.utc).isoformat()
        c = self.conn.cursor()
        c.execute("""
            INSERT INTO forensic_snapshots (
                captured_at, node, trigger, risk_score,
                processes, network_conns, container_state,
                recent_alerts, recent_events, artifact_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ts,
            node,
            trigger,
            risk_score,
            json.dumps(processes),
            json.dumps(network_conns),
            json.dumps(container_state),
            json.dumps(recent_alerts),
            json.dumps(recent_events),
            artifact_path,
        ))
        self.conn.commit()
        row_id = c.lastrowid
        log.info(
            "[FORENSICS] Snapshot stored | node=%s trigger=%s id=%s artifact=%s",
            node, trigger, row_id, artifact_path,
        )
        return row_id

    def get_forensic_snapshots(self, node: str = None, limit: int = 20) -> list:
        """Return forensic snapshots, optionally filtered by node."""
        if node:
            rows = self.conn.execute("""
                SELECT * FROM forensic_snapshots
                WHERE node = ?
                ORDER BY captured_at DESC LIMIT ?
            """, (node, limit)).fetchall()
        else:
            rows = self.conn.execute("""
                SELECT * FROM forensic_snapshots
                ORDER BY captured_at DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]
