"use client";
import { useQuery } from "@tanstack/react-query";
import { getReviewQueue } from "@/services/review.service";

export function useReviewQueue() {
  return useQuery({
    queryKey: ["review-queue"],
    queryFn: getReviewQueue,
    refetchInterval: 5000,
  });
}
