"use client";

// Same card/layout as the login page: form on the left, product panel on the right.
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useRef, useState, type FormEvent } from "react";
import { REGEXP_ONLY_DIGITS } from "input-otp";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { useSession } from "@/lib/session";

export default function RegisterPage() {
  const router = useRouter();
  const { signIn } = useSession();
  const [email, setEmail] = useState("");
  const [tenantName, setTenantName] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState(false);
  const [code, setCode] = useState("");
  const [verifyError, setVerifyError] = useState("");
  const verifying = useRef(false);

  const trimmedEmail = email.trim();
  const trimmedName = tenantName.trim();

  async function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await api.register({ email: trimmedEmail, tenant_name: trimmedName });
      setCreated(true);
      setCode("");
      setVerifyError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not create your account. Try again.");
    } finally {
      setBusy(false);
    }
  }

  async function verify() {
    if (code.length !== 6 || verifying.current || busy) return;
    verifying.current = true;
    setBusy(true);
    setVerifyError("");
    try {
      signIn(await api.verifyCode(trimmedEmail, code));
      router.push("/overview/");
    } catch (e) {
      setVerifyError(e instanceof Error ? e.message : "That code is invalid or expired. Check the newest email, or request a new code.");
      setCode("");
    } finally {
      verifying.current = false;
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-svh items-center justify-center bg-muted p-4 md:p-10">
      <div className="w-full max-w-4xl">
        <Card className="overflow-hidden p-0">
          <CardContent className="grid p-0 md:grid-cols-2">
            <div className="flex flex-col gap-6 p-6 md:p-8">
              {created ? (
                <div className="flex flex-col gap-4" role="status">
                  <div>
                    <h1 className="text-2xl font-semibold tracking-tight">Check your email</h1>
                    <p className="mt-1 text-sm text-muted-foreground">
                      We created a workspace and issued a sign-in code for{" "}
                      <span className="font-medium text-foreground">{trimmedEmail}</span>. It expires in 10 minutes.
                    </p>
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="register-code">6-digit code</Label>
                    <InputOTP id="register-code" maxLength={6} pattern={REGEXP_ONLY_DIGITS} value={code} onChange={setCode} onComplete={verify} autoFocus disabled={busy} autoComplete="one-time-code" inputMode="numeric">
                      <InputOTPGroup>
                        {[0, 1, 2, 3, 4, 5].map((slot) => (
                          <InputOTPSlot key={slot} index={slot} />
                        ))}
                      </InputOTPGroup>
                    </InputOTP>
                  </div>
                  {verifyError && <p role="alert" className="text-sm font-medium">■ {verifyError}</p>}
                  <Button onClick={verify} disabled={busy || code.length !== 6}>{busy ? "Verifying…" : "Verify"}</Button>
                  <p className="text-sm text-muted-foreground">
                    <Link href="/login/" className="font-medium text-foreground underline underline-offset-4">
                      Go to sign in
                    </Link>
                  </p>
                </div>
              ) : (
                <>
                  <div>
                    <h1 className="text-2xl font-semibold tracking-tight">Create your workspace</h1>
                    <p className="mt-1 text-sm text-muted-foreground">
                      Start with a work email and an organisation name. We will issue a one-time sign-in code.
                    </p>
                  </div>

                  <form onSubmit={register} className="flex flex-col gap-4">
                    <div className="grid gap-2">
                      <Label htmlFor="email">Work email</Label>
                      <Input
                        id="email"
                        type="email"
                        autoComplete="username"
                        required
                        disabled={busy}
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="Your work email"
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor="tenant_name">Organisation name</Label>
                      <Input
                        id="tenant_name"
                        autoComplete="organization"
                        required
                        maxLength={100}
                        disabled={busy}
                        value={tenantName}
                        onChange={(e) => setTenantName(e.target.value)}
                        placeholder="Acme Inc."
                      />
                    </div>
                    {error && <p role="alert" className="text-sm font-medium">■ {error}</p>}
                    <Button type="submit" disabled={busy || trimmedEmail === "" || trimmedName === ""}>
                      {busy ? "Creating…" : "Create account"}
                    </Button>
                    <p className="text-sm text-muted-foreground">
                      Already have a workspace?{" "}
                      <Link href="/login/" className="font-medium text-foreground underline underline-offset-4">
                        Sign in
                      </Link>
                    </p>
                  </form>
                </>
              )}
            </div>

            <div className="hidden flex-col justify-between bg-primary p-8 text-primary-foreground md:flex" aria-hidden>
              <span className="font-mono text-sm">lanyard</span>
              <div>
                <p className="text-2xl font-semibold leading-snug tracking-tight">Every agent call is scoped to one task, signed, and on the record.</p>
                <p className="mt-3 max-w-xs text-sm opacity-70">Agents get a badge for the job. Your credentials stay at the proxy.</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
