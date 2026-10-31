"use client";

import { useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";
import { OpsHeader } from "@/components/ops-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useSession } from "@/lib/session";

// Client-side guard for the static export. The /ops API enforces access on every call.
export default function OpsLayout({ children }: { children: ReactNode }) {
  const { state } = useSession();
  const router = useRouter();

  useEffect(() => {
    if (state.status === "anon") router.replace("/login/");
  }, [state.status, router]);

  if (state.status !== "authed") {
    return <p className="p-6 text-sm text-muted-foreground" role="status">Checking your session…</p>;
  }
  return (
    <div className="min-h-svh">
      <OpsHeader />
      <main className="mx-auto flex max-w-6xl flex-col gap-6 p-4 md:p-6">
        {!state.user.hardware_key && (
          <Alert variant="destructive">
            <AlertTitle>■ Hardware key not verified</AlertTitle>
            <AlertDescription>You signed in without a hardware security key, so requesting and deciding actions is disabled. Sign out and sign in again with your key.</AlertDescription>
          </Alert>
        )}
        {children}
      </main>
    </div>
  );
}
