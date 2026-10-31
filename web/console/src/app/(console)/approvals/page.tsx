"use client";

import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, ErrorState, NoAccess, RowsSkeleton } from "@/components/states";
import { Status } from "@/components/status";
import { useResource } from "@/hooks/use-resource";
import { api } from "@/lib/api";
import { can } from "@/lib/roles";
import { useUser } from "@/lib/session";
import type { ApprovalRequest } from "@/lib/types";

export default function ApprovalsPage() {
  const role = useUser()?.role;
  const approvals = useResource(api.approvals.list, can(role, "approvals.read"));
  const [busyId, setBusyId] = useState("");

  if (!can(role, "approvals.read")) return <NoAccess what="approvals" />;

  const items = approvals.data ?? [];
  const pending = items.filter((item) => item.status === "pending");
  const decided = items.filter((item) => item.status !== "pending");

  async function decide(item: ApprovalRequest, status: "approved" | "denied") {
    setBusyId(item.id);
    try {
      await api.approvals.decide(item.id, status, item.parameters);
      toast.success(status === "approved" ? "Approved" : "Denied");
      approvals.reload();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not record the decision.");
    } finally {
      setBusyId("");
    }
  }

  return (
    <div className="grid gap-6">
      {approvals.status === "loading" && <RowsSkeleton />}
      {approvals.status === "error" && <ErrorState message={approvals.error} onRetry={approvals.reload} />}
      {approvals.status === "ready" && pending.length === 0 && <EmptyState title="Nothing is waiting">Requests that need a person's approval appear here.</EmptyState>}

      {pending.map((item) => (
        <Card key={item.id}>
          <CardHeader>
            <CardTitle className="font-mono text-base">{item.action}</CardTitle>
            <CardDescription>Requested by {item.requested_by ?? item.requester_id} for task {item.task_id}. Expires {new Date(item.expires_at).toLocaleString()}.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4">
            {/* Rendered as text in <pre>: agent-supplied parameters can never become markup. */}
            <pre className="max-h-64 overflow-auto border bg-muted p-3 font-mono text-xs">{JSON.stringify(item.parameters ?? {}, null, 2)}</pre>
            {can(role, "approvals.decide") ? (
              <div className="flex flex-wrap gap-2">
                <Button onClick={() => decide(item, "approved")} disabled={busyId === item.id}>Approve</Button>
                <Button variant="outline" onClick={() => decide(item, "denied")} disabled={busyId === item.id}>Deny</Button>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">Your role can view this request but not decide it. You can never decide a request you filed.</p>
            )}
          </CardContent>
        </Card>
      ))}

      {decided.length > 0 && (
        <div className="grid gap-2">
          <h2 className="text-sm font-medium">Decided</h2>
          <div className="overflow-x-auto border">
            <Table>
              <TableHeader><TableRow><TableHead>Action</TableHead><TableHead>Requester</TableHead><TableHead>Status</TableHead><TableHead>Decided by</TableHead></TableRow></TableHeader>
              <TableBody>
                {decided.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell className="font-mono text-xs">{item.action}</TableCell>
                    <TableCell>{item.requester_id}</TableCell>
                    <TableCell><Status value={item.status} /></TableCell>
                    <TableCell>{item.decided_by ?? "–"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      )}
    </div>
  );
}
