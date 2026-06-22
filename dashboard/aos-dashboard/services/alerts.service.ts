import { api } from "@/lib/axios";

export async function getAlerts(params?: {
  severity?: string;
  node_id?: string;
  threat_type?: string;
}) {
  const { data } = await api.get("/alerts", {
    params,
  });

  return data;
}