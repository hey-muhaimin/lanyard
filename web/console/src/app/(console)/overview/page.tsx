"use client";

import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState, ErrorState, RowsSkeleton } from "@/components/states";
import { useResource } from "@/hooks/use-resource";
import { api } from "@/lib/api";
import { can } from "@/lib/roles";
import { useUser } from "@/lib/session";

export default function OverviewPage() {
  const role = useUser()?.role;
  const agents = useResource(api.agents.list, can(role, "agents.read"));
  const approvals = useResource(api.approvals.list, can(role, "approvals.read"));
  const events = useResource(api.events.replay, can(role, "events.read"));
  const pending = (approvals.data ?? []).filter((item) => item.status === "pending");

  return (
    <div className="grid gap-6">
      <div className="grid gap-4 sm:grid-cols-3">
        <Stat title="Agents" value={agents.data?.length} state={agents.status} />
        <Stat title="Waiting for approval" value={can(role, "approvals.read") ? pending.length : undefined} state={approvals.status} />
        <Stat title="Audit events" value={events.data?.length} state={events.status} />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Needs approval</CardTitle>
            <CardDescription>Requests an agent cannot continue without.</CardDescription>
          </CardHeader>
          <CardContent>
            {approvals.status === "loading" && <RowsSkeleton rows={3} />}
            {approvals.status === "error" && <ErrorState message={approvals.error} onRetry={approvals.reload} />}
            {approvals.status === "idle" && <EmptyState title="Not shown for your role" />}
            {approvals.status === "ready" && pending.length === 0 && <EmptyState title="Nothing is waiting">New requests appear here as agents ask for approval.</EmptyState>}
            {approvals.status === "ready" && pending.length > 0 && (
              <ul className="divide-y border">
                {pending.slice(0, 5).map((item) => (
                  <li key={item.id} className="flex items-center justify-between gap-3 p-3">
                    <span className="min-w-0">
                      <span className="block truncate font-mono text-sm">{item.action}</span>
                      <span className="block truncate text-xs text-muted-foreground">from {item.requester_id}</span>
                    </span>
                    <span aria-hidden className="font-mono">◆</span>
                  </li>
                ))}
              </ul>
            )}
            {pending.length > 0 && <Button asChild variant="outline" className="mt-4"><Link href="/approvals/">Review approvals</Link></Button>}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent activity</CardTitle>
            <CardDescription>The latest entries in the audit chain.</CardDescription>
          </CardHeader>
          <CardContent>
            {events.status === "loading" && <RowsSkeleton rows={3} />}
            {events.status === "error" && <ErrorState message={events.error} onRetry={events.reload} />}
            {events.status === "idle" && <EmptyState title="Not shown for your role" />}
            {events.status === "ready" && (events.data ?? []).length === 0 && <EmptyState title="No activity yet">Calls through the proxy are recorded here.</EmptyState>}
            {events.status === "ready" && (events.data ?? []).length > 0 && (
              <ul className="divide-y border">
                {(events.data ?? []).slice(-5).reverse().map((event, index) => (
                  <li key={event.hash ?? index} className="p-3 font-mono text-sm">{String(event.payload?.type ?? "event")}</li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function Stat({ title, value, state }: { title: string; value?: number; state: string }) {
  return (
    <Card>
      <CardHeader>
        <CardDescription>{title}</CardDescription>
        <CardTitle className="font-mono text-3xl tabular-nums">
          {state === "loading" ? "…" : state === "error" ? "■" : value ?? "–"}
        </CardTitle>
      </CardHeader>
    </Card>
  );
}
