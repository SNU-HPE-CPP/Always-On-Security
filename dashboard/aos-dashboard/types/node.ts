export interface NodeSecurity {
  node: string;
  status: string;
  risk_score: number;

  trust_status: string;

  replay_count: number;
  flood_count: number;

  config_tamper_count: number;
  lateral_movement_count: number;

  last_updated: string;
}
export interface NodeIdentity {
  node: string;
  machine_id: string;
  trust_status: string;
  first_seen: string;
  status: string;
  last_seen: string;
}
