"use client";

import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, ErrorState, RowsSkeleton } from "@/components/states";
import { actionLabels, RequestActionSheet } from "@/components/request-action-sheet";
import { Status } from "@/components/status";
import { useResource } from "@/hooks/use-resource";
import { api } from "@/lib/api";
import { can } from "@/lib/roles";
import { useStaff } from "@/lib/session";
import type { OpsAction } from "@/lib/types";

export default function ActionsPage() {
  const user = useStaff();
  const actions = useResource(api.actions.list);
  const [requesting, setRequesting] = useState(false);
  const [busyId, setBusyId] = useState("");
  const keyOk = user?.hardware_key === true;

  const items = actions.data ?? [];
  const pending = items.filter((item) => item.status === "pending");
  const history = items.filter((item) => item.status !== "pending");

  async function decide(item: OpsAction, status: "approved" | "denied") {
    setBusyId(item.id);
    try {
      await api.actions.decide(item.id, status);
      toast.success(status === "approved" ? "Approved. The action was carried out." : "Denied.");
      actions.reload();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not record the decision.");
    } finally {
      setBusyId("");
    }
  }

  return (
    <div className="grid gap-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Incident actions</h1>
          <p className="mt-1 max-w-prose text-sm text-muted-foreground">Every action needs two people: one files it, a different one approves it. Both are recorded.</p>
        </div>
        {can(user?.role, "actions.request") && <Button onClick={() => setRequesting(true)} disabled={!keyOk}>Request an action</Button>}
      </div>

      {actions.status === "loading" && <RowsSkeleton />}
      {actions.status === "error" && <ErrorState message={actions.error} onRetry={actions.reload} />}
      {actions.status === "ready" && pending.length === 0 && <EmptyState title="Nothing is waiting">Filed requests that need a second approver appear here.</EmptyState>}

      {pending.map((item) => {
        const mine = item.requested_by === user?.email;
        return (
          <Card key={item.id}>
            <CardHeader>
              <CardTitle>{actionLabels[item.type]} <span className="font-mono text-sm font-normal">{item.tenant_id === "*" ? "all tenants" : item.tenant_id}</span></CardTitle>
              <CardDescription>Requested by {item.requested_by}. Expires {new Date(item.expires_at).toLocaleTimeString()}. <Status value="pending" /></CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4">
              <p className="max-w-prose text-sm">{item.reason}</p>
              {mine ? (
                <p className="text-sm text-muted-foreground">◆ Waiting for a second approver. You cannot decide your own request.</p>
              ) : can(user?.role, "actions.decide") && keyOk ? (
                <div className="flex flex-wrap gap-2">
                  <Button onClick={() => decide(item, "approved")} disabled={busyId === item.id}>Approve and run</Button>
                  <Button variant="outline" onClick={() => decide(item, "denied")} disabled={busyId === item.id}>Deny</Button>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">Your role or sign-in cannot decide this request.</p>
              )}
            </CardContent>
          </Card>
        );
      })}

      {history.length > 0 && (
        <div className="grid gap-2">
          <h2 className="text-sm font-medium">History</h2>
          <div className="overflow-x-auto border">
            <Table>
              <TableHeader><TableRow><TableHead>Action</TableHead><TableHead>Target</TableHead><TableHead>Requested by</TableHead><TableHead>Decided by</TableHead><TableHead>Result</TableHead></TableRow></TableHeader>
              <TableBody>
                {history.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell>{actionLabels[item.type]}</TableCell>
                    <TableCell className="font-mono text-xs">{item.tenant_id === "*" ? "all tenants" : item.tenant_id}</TableCell>
                    <TableCell>{item.requested_by}</TableCell>
                    <TableCell>{item.decided_by ?? "–"}</TableCell>
                    <TableCell><Status value={item.status} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      )}
      <RequestActionSheet open={requesting} onOpenChange={setRequesting} onDone={actions.reload} />
    </div>
  );
}
