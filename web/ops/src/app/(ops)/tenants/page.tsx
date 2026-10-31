"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, ErrorState, RowsSkeleton } from "@/components/states";
import { RequestActionSheet } from "@/components/request-action-sheet";
import { Status } from "@/components/status";
import { useResource } from "@/hooks/use-resource";
import { api } from "@/lib/api";
import { can } from "@/lib/roles";
import { useStaff } from "@/lib/session";

export default function TenantsPage() {
  const user = useStaff();
  const tenants = useResource(api.tenants.list);
  const [target, setTarget] = useState<string | undefined>();
  const canRequest = can(user?.role, "actions.request") && user?.hardware_key === true;

  return (
    <div className="grid gap-6">
      <h1 className="text-2xl font-semibold tracking-tight">Tenants</h1>
      {tenants.status === "loading" && <RowsSkeleton />}
      {tenants.status === "error" && <ErrorState message={tenants.error} onRetry={tenants.reload} />}
      {tenants.status === "ready" && (tenants.data ?? []).length === 0 && <EmptyState title="No tenants yet">Tenants appear here once a workspace is created.</EmptyState>}
      {tenants.status === "ready" && (tenants.data ?? []).length > 0 && (
        <div className="overflow-x-auto border">
          <Table>
            <TableHeader>
              <TableRow><TableHead>Tenant</TableHead><TableHead>Plan</TableHead><TableHead className="text-right">Agents</TableHead><TableHead className="text-right">Live grants</TableHead><TableHead>State</TableHead><TableHead><span className="sr-only">Actions</span></TableHead></TableRow>
            </TableHeader>
            <TableBody>
              {(tenants.data ?? []).map((tenant) => (
                <TableRow key={tenant.id}>
                  <TableCell><span className="font-medium">{tenant.name}</span> <span className="font-mono text-xs text-muted-foreground">{tenant.id}</span></TableCell>
                  <TableCell>{tenant.plan}</TableCell>
                  <TableCell className="text-right font-mono tabular-nums">{tenant.agents}</TableCell>
                  <TableCell className="text-right font-mono tabular-nums">{tenant.grants}</TableCell>
                  <TableCell><Status value={tenant.state} /></TableCell>
                  <TableCell className="text-right">
                    {canRequest && <Button variant="outline" size="sm" onClick={() => setTarget(tenant.id)}>Request action</Button>}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      <RequestActionSheet key={target ?? "none"} open={target !== undefined} onOpenChange={(open) => !open && setTarget(undefined)} tenantId={target} onDone={tenants.reload} />
    </div>
  );
}
