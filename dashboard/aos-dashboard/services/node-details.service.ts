import { api } from "@/lib/axios";

export async function getNodeDetails(node: string) {
  const { data } = await api.get(`/nodes/${node}/details`);

  return data;
}
