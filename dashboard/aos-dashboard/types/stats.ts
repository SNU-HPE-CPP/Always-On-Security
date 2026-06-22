export interface AlertStats {
  total: number;

  recent_24h: number;

  replay_total: number;

  by_type: Record<string, number>;

  by_severity: Record<string, number>;
}
