"use client";

import { useQuery } from "@tanstack/react-query";

import { getNodeDetails } from "@/services/node-details.service";

export function useNodeDetails(
  node: string
) {
  return useQuery({
    queryKey: ["node-details", node],
    queryFn: () =>
      getNodeDetails(node),
    enabled: !!node,
  });
}