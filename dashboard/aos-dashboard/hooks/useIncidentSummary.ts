"use client";
import { useQuery } from "@tanstack/react-query";
import { getIncidentSummary } from "@/services/review.service";

export function useIncidentSummary(node: string) {
  return useQuery({
    queryKey: ["incident-summary", node],
    queryFn: () => getIncidentSummary(node),
    enabled: !!node,
    refetchInterval: 10000,
  });
}
