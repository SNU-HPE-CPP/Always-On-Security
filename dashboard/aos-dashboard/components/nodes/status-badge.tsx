import { Badge } from "@/components/ui/badge";

export function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    healthy: "bg-green-600 text-white",

    idle: "bg-blue-600 text-white",

    quarantine: "bg-red-600 text-white",

    quarantined: "bg-red-600 text-white",

    unresponsive: "bg-yellow-600 text-black",
  };

  return (
    <Badge className={colors[status] ?? "bg-zinc-700 text-white"}>
      {status}
    </Badge>
  );
}
