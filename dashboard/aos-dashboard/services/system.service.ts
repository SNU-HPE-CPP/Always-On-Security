import { api } from "@/lib/axios";

export async function resetSystem() {
  const { data } = await api.post("/reset");

  return data;
}
