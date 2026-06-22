import { api } from "@/lib/axios";
import { SimulateResult } from "@/types/simulate";

export async function simulateAttack(
  attack: string,
  node?: string,
): Promise<SimulateResult> {
  const { data } = await api.post("/simulate", { attack, node });
  return data;
}
