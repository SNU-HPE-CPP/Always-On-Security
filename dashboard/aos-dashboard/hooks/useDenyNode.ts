"use client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { denyNode } from "@/services/review.service";

export function useDenyNode() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: denyNode,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["review-queue"] });
      queryClient.invalidateQueries({ queryKey: ["nodes"] });
    },
  });
}
