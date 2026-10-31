"use client";

import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, ErrorState, NoAccess, RowsSkeleton } from "@/components/states";
import { Status } from "@/components/status";
import { useResource } from "@/hooks/use-resource";
import { api } from "@/lib/api";
import { can } from "@/lib/roles";
import { useUser } from "@/lib/session";
import type { RevokeScope } from "@/lib/types";

export default function AgentsPage() {
  const role = useUser()?.role;
  const agents = useResource(api.agents.list, can(role, "agents.read"));
  const [registering, setRegistering] = useState(false);

  if (!can(role, "agents.read")) return <NoAccess what="agents" />;
  return (
    <div className="grid gap-6">
      <div className="flex items-start justify-between gap-4">
        <p className="max-w-prose text-sm text-muted-foreground">Each agent signs its requests with its own key. Suspending or revoking an agent stops its next call.</p>
        {can(role, "agents.write") && <Button onClick={() => setRegistering(true)}>Register agent</Button>}
      </div>

      {agents.status === "loading" && <RowsSkeleton />}
      {agents.status === "error" && <ErrorState message={agents.error} onRetry={agents.reload} />}
      {agents.status === "ready" && (agents.data ?? []).length === 0 && (
        <EmptyState title="No agents yet" action={can(role, "agents.write") ? <Button onClick={() => setRegistering(true)}>Register your first agent</Button> : undefined}>
          Register an agent with its public key so it can ask for task badges.
        </EmptyState>
      )}
      {agents.status === "ready" && (agents.data ?? []).length > 0 && (
        <div className="overflow-x-auto border">
          <Table>
            <TableHeader>
              <TableRow><TableHead>Agent</TableHead><TableHead>Owner</TableHead><TableHead>Status</TableHead><TableHead>Public key</TableHead></TableRow>
            </TableHeader>
            <TableBody>
              {(agents.data ?? []).map((agent) => (
                <TableRow key={agent.id}>
                  <TableCell className="font-medium">{agent.id}</TableCell>
                  <TableCell>{agent.owner_subject}</TableCell>
                  <TableCell><Status value={agent.status || "active"} /></TableCell>
                  <TableCell className="max-w-48 truncate font-mono text-xs">{agent.public_key}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {can(role, "revoke") && <RevokeCard />}
      <RegisterSheet open={registering} onOpenChange={setRegistering} onDone={agents.reload} />
    </div>
  );
}

function RegisterSheet({ open, onOpenChange, onDone }: { open: boolean; onOpenChange: (open: boolean) => void; onDone: () => void }) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setBusy(true);
    setError("");
    try {
      await api.agents.create({ id: String(data.get("id")).trim(), owner_subject: String(data.get("owner_subject")).trim(), public_key: String(data.get("public_key")).trim() });
      toast.success("Agent registered");
      form.reset();
      onOpenChange(false);
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not register the agent.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent>
        <form onSubmit={submit} className="flex h-full flex-col">
          <SheetHeader>
            <SheetTitle>Register agent</SheetTitle>
            <SheetDescription>The agent proves who it is by signing with the private key that matches this public key.</SheetDescription>
          </SheetHeader>
          <div className="grid gap-4 px-4">
            <div className="grid gap-2"><Label htmlFor="id">Agent name</Label><Input id="id" name="id" required placeholder="billing-agent" /></div>
            <div className="grid gap-2"><Label htmlFor="owner_subject">Owner</Label><Input id="owner_subject" name="owner_subject" required placeholder="alice@example.com" /></div>
            <div className="grid gap-2"><Label htmlFor="public_key">Public key (base64 Ed25519)</Label><Input id="public_key" name="public_key" required className="font-mono text-xs" /></div>
            {error && <p role="alert" className="text-sm font-medium">■ {error}</p>}
          </div>
          <SheetFooter><Button type="submit" disabled={busy}>{busy ? "Registering…" : "Register agent"}</Button></SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}

const scopes: { value: RevokeScope; label: string }[] = [
  { value: "agent_id", label: "Agent" },
  { value: "task_id", label: "Task" },
  { value: "chain_id", label: "Delegation chain" },
  { value: "token_id", label: "Token" },
];

function RevokeCard() {
  const [scope, setScope] = useState<RevokeScope>("agent_id");
  const [id, setId] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const label = scopes.find((item) => item.value === scope)?.label.toLowerCase();

  async function revoke() {
    setBusy(true);
    try {
      await api.revoke(scope, id.trim());
      toast.success(`Access revoked for ${label} ${id.trim()}`);
      setId("");
      setConfirming(false);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not revoke access.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Revoke access</CardTitle>
        <CardDescription>Stops an agent, task, delegation chain, or token. Calls using it fail on their next request.</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="flex flex-wrap items-end gap-3" onSubmit={(event) => { event.preventDefault(); setConfirming(true); }}>
          <div className="grid gap-2">
            <Label htmlFor="revoke-scope">What to revoke</Label>
            <Select value={scope} onValueChange={(value) => setScope(value as RevokeScope)}>
              <SelectTrigger id="revoke-scope" className="w-48"><SelectValue /></SelectTrigger>
              <SelectContent>{scopes.map((item) => <SelectItem key={item.value} value={item.value}>{item.label}</SelectItem>)}</SelectContent>
            </Select>
          </div>
          <div className="grid min-w-48 flex-1 gap-2"><Label htmlFor="revoke-id">Identifier</Label><Input id="revoke-id" value={id} onChange={(e) => setId(e.target.value)} required className="font-mono" /></div>
          <Button type="submit" variant="outline" disabled={id.trim() === ""}>Revoke access</Button>
        </form>
      </CardContent>
      <Dialog open={confirming} onOpenChange={setConfirming}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke access for {label} {id.trim()}?</DialogTitle>
            <DialogDescription>Anything using it stops working on its next request. This is recorded in the audit log.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirming(false)}>Keep access</Button>
            <Button onClick={revoke} disabled={busy}>{busy ? "Revoking…" : "Revoke access"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
