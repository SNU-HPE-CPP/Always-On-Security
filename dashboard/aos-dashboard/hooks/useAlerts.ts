"use client";

import { useQuery } from "@tanstack/react-query";

import { getAlerts } from "@/services/alerts.service";

export function useAlerts(filters: {
  severity?: string;
  node_id?: string;
  threat_type?: string;
}) {
  return useQuery({
    queryKey: ["alerts", filters],
    queryFn: () => getAlerts(filters),
    refetchInterval: 5000,
  });
}
