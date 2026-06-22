import { NodesTable } from "@/components/nodes/nodes-table";

export default function NodesPage() {
  return (
    <div className="mx-auto max-w-7xl p-8 space-y-6">
      <div>
        <h1 className="text-4xl font-bold text-white">Nodes</h1>

        <p className="text-zinc-400">
          Cluster asset inventory and security posture.
        </p>
      </div>

      <NodesTable />
    </div>
  );
}
