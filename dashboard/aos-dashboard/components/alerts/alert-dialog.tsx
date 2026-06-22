"use client";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface AlertDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  alert: any;
}

export function AlertDialog({ open, onOpenChange, alert }: AlertDialogProps) {
  if (!alert) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="
          max-w-6xl
          w-[90vw]
          border-zinc-800
          bg-zinc-950
          text-white
          max-h-[90vh]
          overflow-hidden
        "
      >
        <DialogHeader>
          <DialogTitle className="text-xl">{alert.threat_type}</DialogTitle>
        </DialogHeader>

        <div className="space-y-6 overflow-y-auto pr-2">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <p className="text-xs uppercase tracking-wide text-zinc-500">
                Severity
              </p>

              <p className="mt-1 font-medium">{alert.severity}</p>
            </div>

            <div>
              <p className="text-xs uppercase tracking-wide text-zinc-500">
                Node
              </p>

              <p className="mt-1 font-medium">{alert.node_id}</p>
            </div>
          </div>

          <div>
            <p className="text-xs uppercase tracking-wide text-zinc-500">
              Description
            </p>

            <p className="mt-2 text-zinc-300">{alert.description}</p>
          </div>

          <div>
            <p className="text-xs uppercase tracking-wide text-zinc-500">
              Recommended Action
            </p>

            <p className="mt-2 text-zinc-300">{alert.recommended_action}</p>
          </div>

          <div>
            <p className="mb-2 text-xs uppercase tracking-wide text-zinc-500">
              Evidence
            </p>

            <pre
              className="
                max-h-[400px]
                overflow-auto
                rounded-lg
                border
                border-zinc-800
                bg-black
                p-4
                text-xs
                text-green-400
                whitespace-pre-wrap
                break-words
              "
            >
              {JSON.stringify(alert.evidence, null, 2)}
            </pre>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
