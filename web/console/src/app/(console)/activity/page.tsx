"use client";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { EmptyState, ErrorState, NoAccess, RowsSkeleton } from "@/components/states";
import { useResource } from "@/hooks/use-resource";
import { api } from "@/lib/api";
import { can } from "@/lib/roles";
import { useUser } from "@/lib/session";

export default function ActivityPage() {
  const role = useUser()?.role;
  const events = useResource(api.events.replay, can(role, "events.read"));
  const items = events.data ?? [];
  // The API answers 409 when the hash chain does not verify.
  const chainBroken = events.status === "error" && events.error?.toLowerCase().includes("chain");

  if (!can(role, "events.read")) return <NoAccess what="activity" />;
  return (
    <div className="grid gap-6">
      {events.status === "loading" && <RowsSkeleton rows={5} />}
      {chainBroken && (
        <Alert variant="destructive">
          <AlertTitle>■ Audit chain failed verification</AlertTitle>
          <AlertDescription>{events.error}. Treat this log as untrusted and contact your platform admin.</AlertDescription>
        </Alert>
      )}
      {events.status === "error" && !chainBroken && <ErrorState message={events.error} onRetry={events.reload} />}
      {events.status === "ready" && items.length === 0 && <EmptyState title="No activity yet">Every grant, approval, revocation and proxied call is recorded here once agents start working.</EmptyState>}
      {events.status === "ready" && items.length > 0 && (
        <>
          <p className="text-sm"><span aria-hidden className="font-mono">● </span>Chain verified · {items.length} events</p>
          <ol className="divide-y border">
            {items.map((event, index) => (
              <li key={event.hash ?? index} className="grid gap-1 p-3">
                <span className="font-mono text-sm font-medium">{String(event.payload?.type ?? "event")}</span>
                <pre className="overflow-x-auto font-mono text-xs text-muted-foreground">{JSON.stringify(event.payload ?? {}, null, 2)}</pre>
                {event.hash && <span className="truncate font-mono text-xs text-muted-foreground">hash {event.hash}</span>}
              </li>
            ))}
          </ol>
        </>
      )}
    </div>
  );
}
