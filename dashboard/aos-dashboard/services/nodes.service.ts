import { api } from "@/lib/axios";
import { NodeIdentity } from "@/types/node";

export async function getNodes() {
  const { data } = await api.get("/nodes/security");
  return data;
}

export const getNodeIdentity = async (): Promise<NodeIdentity[]> => {
  const { data } = await api.get("/nodes/identity");
  return data;
};

export const approveNode = async (node: string) => {
  const { data } = await api.post(`/nodes/${node}/approve`);

  return data;
};

export const restartNode = async (node: string) => {
  const { data } = await api.post(`/nodes/${node}/restart`);

  return data;
};
