"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";

import { restartNode } from "@/services/nodes.service";

export function useRestartNode() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: restartNode,

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
