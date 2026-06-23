"use client";

import { useQuery } from "@tanstack/react-query";

import {
  getNodes,
  getRecentAlerts,
  getStats,
  getEvents,
} from "@/services/dashboard.service";

export function useStats() {
  return useQuery({
    queryKey: ["stats"],
    queryFn: getStats,
    refetchInterval: 5000,
  });
}

export function useNodes() {
  return useQuery({
    queryKey: ["nodes"],
    queryFn: getNodes,
    refetchInterval: 5000,
  });
}

export function useAlerts() {
  return useQuery({
    queryKey: ["alerts"],
    queryFn: getRecentAlerts,
    refetchInterval: 5000,
  });
}

export function useEvents() {
  return useQuery({
    queryKey: ["events"],
    queryFn: getEvents,
    refetchInterval: 5000,
  });
}
