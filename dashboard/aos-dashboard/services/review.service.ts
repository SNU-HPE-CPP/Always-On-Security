import { api } from "@/lib/axios";
import { ReviewQueueItem, IncidentSummary } from "@/types/review";

export const getReviewQueue = async (): Promise<ReviewQueueItem[]> => {
  const { data } = await api.get("/review/queue");
  return data;
};

export const getIncidentSummary = async (node: string): Promise<IncidentSummary> => {
  const { data } = await api.get(`/incident-summary/${node}`);
  return data;
};

export const denyNode = async ({ node, notes }: { node: string; notes: string }) => {
  const { data } = await api.post(`/nodes/${node}/deny`, { notes });
  return data;
};

export const approveNodeWithNotes = async ({ node, notes }: { node: string; notes: string }) => {
  const { data } = await api.post(`/nodes/${node}/approve`, { notes });
  return data;
};
