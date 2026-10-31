"use client";

import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { useResource } from "@/hooks/use-resource";
import { api } from "@/lib/api";
import type { ActionType } from "@/lib/types";

export const actionLabels: Record<ActionType, string> = {
  suspend_tenant: "Suspend tenant",
  rotate_signing_key: "Rotate signing key",
  view_as_customer: "View as customer",
};

const MIN_REASON = 20;

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  tenantId?: string;
  onDone: () => void;
}

// Filing a request never performs the action: a second person has to approve it.
export function RequestActionSheet({ open, onOpenChange, tenantId, onDone }: Props) {
  const tenants = useResource(api.tenants.list, open);
  const [type, setType] = useState<ActionType>("suspend_tenant");
  const [tenant, setTenant] = useState(tenantId ?? "");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const platformWide = type === "rotate_signing_key";
  const target = platformWide ? "*" : tenantId ?? tenant;
  const valid = target !== "" && reason.trim().length >= MIN_REASON;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.actions.create({ type, tenant_id: target, reason: reason.trim() });
      toast.success("Request filed. A second person must approve it before anything happens.");
      setReason("");
      onOpenChange(false);
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not file the request.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent>
        <form onSubmit={submit} className="flex h-full flex-col">
          <SheetHeader>
            <SheetTitle>Request an action</SheetTitle>
            <SheetDescription>Nothing runs until a different person approves. Your request and the approval are both written to the audit log.</SheetDescription>
          </SheetHeader>
          <div className="grid gap-4 px-4">
            <div className="grid gap-2">
              <Label htmlFor="action-type">Action</Label>
              <Select value={type} onValueChange={(value) => setType(value as ActionType)}>
                <SelectTrigger id="action-type"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {(Object.keys(actionLabels) as ActionType[]).map((key) => <SelectItem key={key} value={key}>{actionLabels[key]}</SelectItem>)}
                </SelectContent>
              </Select>
              {type === "view_as_customer" && <p className="text-xs text-muted-foreground">Needs the customer's consent on record. Access is read-only and time-limited.</p>}
            </div>
            {!platformWide && !tenantId && (
              <div className="grid gap-2">
                <Label htmlFor="action-tenant">Tenant</Label>
                <Select value={tenant} onValueChange={setTenant}>
                  <SelectTrigger id="action-tenant"><SelectValue placeholder={tenants.status === "loading" ? "Loading…" : "Choose a tenant"} /></SelectTrigger>
                  <SelectContent>{(tenants.data ?? []).map((item) => <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>)}</SelectContent>
                </Select>
              </div>
            )}
            {platformWide && <p className="text-sm">This affects every tenant.</p>}
            <div className="grid gap-2">
              <Label htmlFor="action-reason">Reason</Label>
              <Textarea id="action-reason" value={reason} onChange={(e) => setReason(e.target.value)} rows={4} placeholder="What happened, and why this action?" />
              <p className="text-xs text-muted-foreground">{reason.trim().length}/{MIN_REASON} characters minimum</p>
            </div>
            {error && <p role="alert" className="text-sm font-medium">■ {error}</p>}
          </div>
          <SheetFooter><Button type="submit" disabled={busy || !valid}>{busy ? "Filing…" : "File request"}</Button></SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
