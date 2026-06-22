"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useNodeIdentity } from "@/hooks/useNodeIdentity";

interface Props {
  node: string;
}

export function NodeIdentityCard({ node }: Props) {
  const { data: identity, isLoading } = useNodeIdentity(node);

  if (isLoading) {
    return (
      <Card className="border-zinc-800 bg-zinc-900">
        <CardContent className="p-6">Loading identity...</CardContent>
      </Card>
    );
  }

  if (!identity) {
    return (
      <Card className="border-zinc-800 bg-zinc-900">
        <CardContent className="p-6">No identity data available</CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-zinc-800 bg-zinc-900">
      <CardHeader>
        <CardTitle>Identity Information</CardTitle>
      </CardHeader>

      <CardContent className="space-y-4">
        <div>
          <p className="text-xs text-zinc-500">Machine ID</p>

          <p className="break-all font-mono text-sm text-white">
            {identity.machine_id}
          </p>
        </div>

        <div>
          <p className="text-xs text-zinc-500">Trust Status</p>

          <p
            className={`font-semibold ${
              identity.trust_status === "TRUSTED"
                ? "text-green-400"
                : identity.trust_status === "SUSPECT"
                  ? "text-yellow-400"
                  : "text-red-400"
            }`}
          >
            {identity.trust_status}
          </p>
        </div>

        <div>
          <p className="text-xs text-zinc-500">First Seen</p>

          <p className="text-white">
            {new Date(identity.first_seen).toLocaleString()}
          </p>
        </div>

        <div>
          <p className="text-xs text-zinc-500">Last Seen</p>

          <p className="text-white">
            {new Date(identity.last_seen).toLocaleString()}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
