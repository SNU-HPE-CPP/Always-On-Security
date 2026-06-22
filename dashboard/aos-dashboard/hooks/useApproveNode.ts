"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";

import { approveNode } from "@/services/nodes.service";

export function useApproveNode() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: approveNode,

    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["nodes"],
      });

      queryClient.invalidateQueries({
        queryKey: ["node-identity"],
      });
    },
  });
}
