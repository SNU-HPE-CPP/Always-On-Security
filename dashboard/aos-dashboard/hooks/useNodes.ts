"use client";

import { useQuery } from "@tanstack/react-query";

import { getNodes } from "@/services/nodes.service";

export function useNodes() {
  return useQuery({
    queryKey: ["nodes"],
    queryFn: getNodes,
    refetchInterval: 5000,
  });
}
