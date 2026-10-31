"use client";

// Layout follows shadcn's login-04 block: one bordered card, form on the left, product panel on the right.
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { REGEXP_ONLY_DIGITS } from "input-otp";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { useSession } from "@/lib/session";

const RESEND_SECONDS = 30;

export function LoginForm() {
  const router = useRouter();
  const { state, signIn } = useSession();
  const [step, setStep] = useState<"email" | "code">("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [wait, setWait] = useState(0);
  const verifying = useRef(false);

  useEffect(() => {
    if (state.status === "authed") router.replace("/overview/");
  }, [state.status, router]);

  useEffect(() => {
    if (wait <= 0) return;
    const timer = setTimeout(() => setWait((value) => value - 1), 1000);
    return () => clearTimeout(timer);
  }, [wait]);

  async function sendCode(event?: FormEvent) {
    event?.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.requestCode(email.trim());
      setMessage("If that address belongs to a Lanyard workspace, we sent a 6-digit code. It expires in 10 minutes.");
      setStep("code");
      setWait(RESEND_SECONDS);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not send a code. Try again.");
    } finally {
      setBusy(false);
    }
  }

  async function verify(value: string) {
    if (value.length !== 6 || verifying.current) return;
    verifying.current = true;
    setBusy(true);
    setError("");
    try {
      signIn(await api.verifyCode(email.trim(), value));
      router.replace("/overview/");
    } catch {
      setError("That code is invalid or expired. Check the newest email, or request a new code.");
      setCode("");
    } finally {
      verifying.current = false;
      setBusy(false);
    }
  }

  return (
    <Card className="overflow-hidden p-0">
      <CardContent className="grid p-0 md:grid-cols-2">
        <div className="flex flex-col gap-6 p-6 md:p-8">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Sign in to Lanyard</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              {step === "email" ? "Enter your work email. We will send you a one-time code." : `Enter the code sent to ${email.trim()}.`}
            </p>
          </div>

          {step === "email" ? (
            <form onSubmit={sendCode} className="flex flex-col gap-4">
              <div className="grid gap-2">
                <Label htmlFor="email">Work email</Label>
                <Input id="email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="alice@example.com" />
              </div>
              {error && <p role="alert" className="text-sm font-medium">■ {error}</p>}
              <Button type="submit" disabled={busy || email.trim() === ""}>{busy ? "Sending…" : "Email me a code"}</Button>
              <p className="text-sm text-muted-foreground">
                New to Lanyard?{" "}
                <Link href="/register/" className="font-medium text-foreground underline underline-offset-4">
                  Create an account
                </Link>
              </p>
            </form>
          ) : (
            <div className="flex flex-col gap-4">
              <div className="grid gap-2">
                <Label htmlFor="code">6-digit code</Label>
                <InputOTP id="code" maxLength={6} pattern={REGEXP_ONLY_DIGITS} value={code} onChange={setCode} onComplete={verify} autoFocus disabled={busy} autoComplete="one-time-code" inputMode="numeric">
                  <InputOTPGroup>
                    {[0, 1, 2, 3, 4, 5].map((slot) => (
                      <InputOTPSlot key={slot} index={slot} />
                    ))}
                  </InputOTPGroup>
                </InputOTP>
              </div>
              {message && !error && <p role="status" className="text-sm text-muted-foreground">{message}</p>}
              {error && <p role="alert" className="text-sm font-medium">■ {error}</p>}
              <Button onClick={() => verify(code)} disabled={busy || code.length !== 6}>{busy ? "Checking…" : "Sign in"}</Button>
              <div className="flex flex-wrap gap-2">
                <Button variant="outline" onClick={() => void sendCode()} disabled={busy || wait > 0}>{wait > 0 ? `Resend code in ${wait}s` : "Resend code"}</Button>
                <Button variant="ghost" onClick={() => { setStep("email"); setCode(""); setError(""); }}>Use a different email</Button>
              </div>
            </div>
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
  );
}
