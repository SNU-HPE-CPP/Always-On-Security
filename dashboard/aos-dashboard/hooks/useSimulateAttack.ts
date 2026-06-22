"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { simulateAttack } from "@/services/simulate.service";

export function useSimulateAttack() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      attack,
      node,
    }: {
      attack: string;
      node?: string;
    }) => simulateAttack(attack, node),

    onSuccess: () => {
      // Refresh alerts, stats, and node data so results appear immediately
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      queryClient.invalidateQueries({ queryKey: ["stats"] });
      queryClient.invalidateQueries({ queryKey: ["nodes"] });
      queryClient.invalidateQueries({ queryKey: ["node-security"] });
    },
  });
}
