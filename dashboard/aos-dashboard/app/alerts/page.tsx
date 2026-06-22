import { AlertsTable } from "@/components/alerts/alerts-table";

export default function AlertsPage() {
  return (
    <div className="mx-auto max-w-7xl space-y-6 p-8">
      <div>
        <h1 className="text-4xl font-bold text-white">Alerts</h1>

        <p className="text-zinc-400">
          Security incidents detected across the cluster.
        </p>
      </div>

      <AlertsTable />
    </div>
  );
}
