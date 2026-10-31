import type { Metadata } from "next";
import { LoginForm } from "@/components/login-form";

export const metadata: Metadata = { title: "Sign in" };

export default function LoginPage() {
  return (
    <main className="flex min-h-svh items-center justify-center bg-muted p-4 md:p-10">
      <div className="w-full max-w-4xl">
        <LoginForm />
      </div>
    </main>
  );
}
