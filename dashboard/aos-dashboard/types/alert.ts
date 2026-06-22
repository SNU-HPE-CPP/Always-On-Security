export interface Alert {
  id: number;
  alert_id: string;
  timestamp: string;
  node_id: string;
  severity: string;
  threat_type: string;
  description: string;
  recommended_action: string;
  evidence: Record<string, unknown>;
}
