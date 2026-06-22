export type AttackCategory = "all" | "protocol" | "exec" | "network" | "config" | "correlated";

export interface AttackDefinition {
  id: string;
  category: Exclude<AttackCategory, "all">;
  name: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  expectedAlerts: string[];
  nodeSpecific: boolean;
}

export interface SimLog {
  id: string;
  attackId: string;
  attackName: string;
  node?: string;
  firedAt: Date;
  status: "pending" | "success" | "error";
  message: string;
}

export interface SimulateResult {
  ok: boolean;
  message?: string;
  error?: string;
}
