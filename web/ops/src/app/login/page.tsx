"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { isMock } from "@/lib/api";
import { useSession } from "@/lib/session";

// Staff sign-in happens at the company identity provider (SSO with a hardware security key).
// This page only starts that flow; it never sees a password or a code.
export default function LoginPage() {
  const { state } = useSession();
  const router = useRouter();
  useEffect(() => {
    if (state.status === "authed") router.replace("/health/");
  }, [state.status, router]);

  return (
    <main className="flex min-h-svh flex-col bg-muted">
      <div className="bg-primary px-4 py-3 font-mono text-sm text-primary-foreground">lanyard ops · internal</div>
      <div className="flex flex-1 items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle className="text-2xl">Staff sign-in</CardTitle>
            <CardDescription>Lanyard employees only. You will sign in with company SSO and a hardware security key. Every action here is recorded.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3">
            <Button asChild>
              <a href={isMock ? "/health/" : "/ops/auth/login"}>Continue with company SSO</a>
            </Button>
            {state.status === "anon" && <p className="text-sm text-muted-foreground">You are not signed in, or your session ended.</p>}
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
