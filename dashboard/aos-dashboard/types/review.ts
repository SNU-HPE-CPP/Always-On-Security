export interface ReviewQueueItem {
  node: string;
  risk_score: number;
  status: string;
  last_updated: string;
  isolated_ip: string | null;
  alert_count: number;
  top_threat: string | null;
}

export interface TimelineEntry {
  timestamp: string;
  display_time: string;
  ago: string;
  event_type: string;
  severity: string;
  description: string;
  mitre_id: string;
  mitre_name: string;
  source: "security_alert" | "risk_event";
  risk_score?: number;
  correlated?: boolean;
}

export interface CorrelationFinding {
  label: string;
  multiplier: number;
  matched_types: string[];
}

export interface TopThreat {
  threat_type: string;
  count: number;
  severity: string;
}

export interface RiskTrajectoryPoint {
  timestamp: string;
  display_time: string;
  score: number;
}

export interface MitreTechnique {
  id: string;
  name: string;
  triggered_by: string;
}

export interface ForensicSummary {
  captured_at: string;
  trigger: string;
  process_count: number;
  network_connections: number;
  container_image: string;
  container_pid: string | number;
  artifact_path: string;
}

export interface IncidentSummary {
  node: string;
  risk_score: number;
  status: string;
  paused_at: string;
  confidence_level: "HIGH" | "MEDIUM" | "LOW";
  recommended_action: "QUARANTINE" | "INVESTIGATE_FURTHER" | "APPROVE_AND_RESUME";
  narrative: string;
  top_threats: TopThreat[];
  timeline: TimelineEntry[];
  correlations: CorrelationFinding[];
  risk_trajectory: RiskTrajectoryPoint[];
  enforcement_actions: string[];
  nist_references: string[];
  mitre_techniques: MitreTechnique[];
  forensic_summary: ForensicSummary | null;
  total_events: number;
  total_alerts: number;
}
