"use client";

import { Badge } from "@/components/ui/badge";

interface Props {
  severity: string;
}

export function SeverityBadge({ severity }: Props) {
  const colors: Record<string, string> = {
    CRITICAL: "bg-red-600 hover:bg-red-600 text-white",

    HIGH: "bg-orange-600 hover:bg-orange-600 text-white",

    MEDIUM: "bg-yellow-600 hover:bg-yellow-600 text-black",

    LOW: "bg-green-600 hover:bg-green-600 text-white",

    INFO: "bg-blue-600 hover:bg-blue-600 text-white",
  };

  return (
    <Badge className={colors[severity] ?? "bg-zinc-600 text-white"}>
      {severity}
    </Badge>
  );
}
