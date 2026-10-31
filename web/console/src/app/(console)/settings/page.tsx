"use client";

import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { EmptyState, ErrorState, RowsSkeleton } from "@/components/states";
import { Status } from "@/components/status";
import { useResource } from "@/hooks/use-resource";
import { api } from "@/lib/api";
import { can } from "@/lib/roles";
import { useUser } from "@/lib/session";
import type { Tenant } from "@/lib/types";

export default function SettingsPage() {
  const role = useUser()?.role;
  const tenant = useResource(api.tenant.get);

  if (tenant.status === "loading") return <RowsSkeleton rows={6} />;
  if (tenant.status === "error") return <ErrorState message={tenant.error} onRetry={tenant.reload} />;
  if (tenant.status !== "ready" || !tenant.data) {
    return (
      <EmptyState
        title="No workspace profile"
        action={<Button variant="outline" onClick={tenant.reload}>Try again</Button>}
      >
        The control plane did not return profile details for this workspace.
      </EmptyState>
    );
  }

  return <TenantProfile tenant={tenant.data} canManage={can(role, "members.manage")} onSaved={tenant.reload} />;
}

interface FormErrors {
  name?: string;
  contact?: string;
}

function TenantProfile({ tenant, canManage, onSaved }: { tenant: Tenant; canManage: boolean; onSaved: () => void }) {
  const [name, setName] = useState(tenant.name);
  const [contact, setContact] = useState(tenant.contact_email ?? "");
  const [errors, setErrors] = useState<FormErrors>({});
  const [formError, setFormError] = useState("");
  const [busy, setBusy] = useState(false);

  function validate(trimmedName: string, trimmedContact: string): boolean {
    const next: FormErrors = {};
    if (trimmedName.length === 0) next.name = "Enter an organisation name.";
    else if (trimmedName.length > 100) next.name = "Use 100 characters or fewer.";
    if (trimmedContact !== "" && !trimmedContact.includes("@")) {
      next.contact = "Enter an email address containing @, or leave this blank.";
    }
    setErrors(next);
    return Object.keys(next).length === 0;
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canManage || busy) return;
    const trimmedName = name.trim();
    const trimmedContact = contact.trim();
    setFormError("");
    if (!validate(trimmedName, trimmedContact)) return;

    const payload: { name?: string; contact_email?: string | null } = {};
    if (trimmedName !== tenant.name.trim()) {
      payload.name = trimmedName;
    }
    const currentContact = (tenant.contact_email ?? "").trim();
    if (trimmedContact !== currentContact) {
      payload.contact_email = trimmedContact === "" ? null : trimmedContact;
    }
    if (Object.keys(payload).length === 0) {
      setFormError("No changes to save");
      return;
    }

    setBusy(true);
    try {
      const updated = await api.tenant.update(payload);
      setName(updated.name);
      setContact(updated.contact_email ?? "");
      toast.success("Workspace profile saved");
      onSaved();
    } catch (e) {
      setFormError(e instanceof Error ? e.message : "Could not save the profile.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid gap-6">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">Workspace settings</h1>
        <p className="mt-1 max-w-prose text-sm text-muted-foreground">
          Profile details for this workspace. Admins can change the name and contact email.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Profile</CardTitle>
          <CardDescription>Used on approvals, notifications, and the audit record.</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={save} noValidate className="grid max-w-xl gap-4">
            <div className="grid gap-2">
              <Label htmlFor="tenant-name">Organisation name</Label>
              <Input
                id="tenant-name"
                required
                maxLength={100}
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={busy}
                readOnly={!canManage}
                aria-invalid={errors.name ? true : undefined}
                aria-describedby={errors.name ? "tenant-name-error" : undefined}
              />
              {errors.name && <p id="tenant-name-error" role="alert" className="text-sm font-medium">■ {errors.name}</p>}
            </div>

            <div className="grid gap-2">
              <Label htmlFor="tenant-contact">Contact email</Label>
              <Input
                id="tenant-contact"
                type="email"
                autoComplete="email"
                value={contact}
                onChange={(e) => setContact(e.target.value)}
                disabled={busy}
                readOnly={!canManage}
                aria-invalid={errors.contact ? true : undefined}
                aria-describedby={errors.contact ? "tenant-contact-error" : "tenant-contact-hint"}
                placeholder="Optional"
              />
              {errors.contact ? (
                <p id="tenant-contact-error" role="alert" className="text-sm font-medium">■ {errors.contact}</p>
              ) : (
                <p id="tenant-contact-hint" className="text-sm text-muted-foreground">Leave blank if you do not want a contact address on record.</p>
              )}
            </div>

            {formError && <p role="alert" className="text-sm font-medium">■ {formError}</p>}
            {!canManage && (
              <p id="tenant-save-disabled-note" className="text-sm text-muted-foreground">Only workspace admins can change these details. You can still review them here.</p>
            )}
            <div>
              <Button type="submit" disabled={!canManage || busy} aria-describedby={!canManage ? "tenant-save-disabled-note" : undefined}>{busy ? "Saving…" : "Save changes"}</Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Tenant details</CardTitle>
          <CardDescription>Read-only identifiers assigned by the control plane.</CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-3 text-sm">
            <div className="grid gap-1 border-b pb-3 sm:grid-cols-[12rem_1fr] sm:items-center">
              <dt className="text-muted-foreground">Tenant ID</dt>
              <dd className="break-all font-mono text-xs">{tenant.id}</dd>
            </div>
            <div className="grid gap-1 border-b pb-3 sm:grid-cols-[12rem_1fr] sm:items-center">
              <dt className="text-muted-foreground">Plan</dt>
              <dd>{tenant.plan}</dd>
            </div>
            <div className="grid gap-1 border-b pb-3 sm:grid-cols-[12rem_1fr] sm:items-center">
              <dt className="text-muted-foreground">Status</dt>
              <dd><Status value={tenant.status || "Unknown"} /></dd>
            </div>
            <div className="grid gap-1 sm:grid-cols-[12rem_1fr] sm:items-center">
              <dt className="text-muted-foreground">Created</dt>
              <dd className="font-mono text-xs">{tenant.created_at}</dd>
            </div>
          </dl>
        </CardContent>
      </Card>
    </div>
  );
}
