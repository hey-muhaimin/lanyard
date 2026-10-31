"use client";

import { useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";
import { AppSidebar } from "@/components/app-sidebar";
import { SiteHeader } from "@/components/site-header";
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { useSession } from "@/lib/session";

// Client-side guard: the static export has no server to redirect. The API enforces access on every call.
export default function ConsoleLayout({ children }: { children: ReactNode }) {
  const { state } = useSession();
  const router = useRouter();

  useEffect(() => {
    if (state.status === "anon") router.replace("/login/");
  }, [state.status, router]);

  if (state.status !== "authed") {
    return <p className="p-6 text-sm text-muted-foreground" role="status">Checking your session…</p>;
  }
  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <SiteHeader />
        <main className="flex flex-1 flex-col gap-6 p-4 md:p-6">{children}</main>
      </SidebarInset>
    </SidebarProvider>
  );
}
