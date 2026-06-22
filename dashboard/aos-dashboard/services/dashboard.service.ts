import { api } from "@/lib/axios";

export async function getStats() {
  const { data } = await api.get("/alerts/stats");
  return data;
}

export async function getNodes() {
  const { data } = await api.get("/nodes/security");
  return data;
}

export async function getRecentAlerts() {
  const { data } = await api.get("/alerts?limit=10");
  return data;
}

