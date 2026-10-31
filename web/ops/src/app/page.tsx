"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { useSession } from "@/lib/session";

export default function Home() {
  const { state } = useSession();
  const router = useRouter();
  useEffect(() => {
    if (state.status === "authed") router.replace("/health/");
    if (state.status === "anon") router.replace("/login/");
  }, [state.status, router]);
  return <p className="p-6 text-sm text-muted-foreground">Loading…</p>;
}
