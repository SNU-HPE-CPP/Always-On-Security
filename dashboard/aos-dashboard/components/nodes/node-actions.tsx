"use client";

import { toast } from "sonner";
import { CheckCircle, RotateCcw } from "lucide-react";

import { Button } from "@/components/ui/button";

import { useApproveNode } from "@/hooks/useApproveNode";
import { useRestartNode } from "@/hooks/useRestartNode";

interface Props {
  node: string;
  status?: string;
}

export function NodeActions({ node, status }: Props) {
  const approveMutation = useApproveNode();
  const restartMutation = useRestartNode();

  const handleApprove = async () => {
    try {
      await approveMutation.mutateAsync(node);

      toast.success("Node approved");
    } catch {
      toast.error("Approve failed");
    }
  };

  const handleRestart = async () => {
    try {
      await restartMutation.mutateAsync(node);

      toast.success("Node restarted");
    } catch {
      toast.error("Restart failed");
    }
  };

  return (
    <div className="flex gap-3">
      {status === "awaiting_approval" && (
        <Button
          onClick={handleApprove}
          disabled={approveMutation.isPending}
          className="bg-green-600 hover:bg-green-700"
        >
          <CheckCircle className="mr-2 h-4 w-4" />
          Approve
        </Button>
      )}

      <Button
        onClick={handleRestart}
        disabled={restartMutation.isPending}
        variant="destructive"
      >
        <RotateCcw className="mr-2 h-4 w-4" />
        Restart
      </Button>
    </div>
  );
}
