"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { ChevronDown, LogOut } from "lucide-react";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { isMock } from "@/lib/api";
import { roleLabels } from "@/lib/roles";
import { useSession, useStaff } from "@/lib/session";

const links = [
  { title: "Health", href: "/health/" },
  { title: "Tenants", href: "/tenants/" },
  { title: "Actions", href: "/actions/" },
];

// Dark header on purpose: a different look from the customer console, so staff never mistake one for the other.
export function OpsHeader() {
  const pathname = usePathname();
  const router = useRouter();
  const user = useStaff();
  const { signOut } = useSession();
  const env = process.env.NEXT_PUBLIC_OPS_ENV ?? "local";

  return (
    <header className="bg-primary text-primary-foreground">
      <div className="flex min-h-14 flex-wrap items-center gap-x-6 gap-y-1 px-4 md:px-6">
        <span className="font-mono text-sm">lanyard ops · internal</span>
        <span className="border border-primary-foreground/50 px-2 py-0.5 font-mono text-xs uppercase">{env}</span>
        {isMock && <span className="font-mono text-xs opacity-70">mock data</span>}
        <nav aria-label="Main" className="flex gap-1 overflow-x-auto">
          {links.map((link) => {
            const active = pathname === link.href || pathname === link.href.slice(0, -1);
            return (
              <Link key={link.href} href={link.href} aria-current={active ? "page" : undefined}
                className={`border-b-2 px-3 py-4 text-sm ${active ? "border-primary-foreground" : "border-transparent opacity-70 hover:opacity-100"}`}>
                {link.title}
              </Link>
            );
          })}
        </nav>
        {user && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="ml-auto text-primary-foreground hover:bg-primary-foreground/10 hover:text-primary-foreground">
                <span className="max-w-48 truncate">{user.email}</span>
                <ChevronDown />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="min-w-56">
              <DropdownMenuLabel className="font-normal">
                <span className="block truncate text-sm font-medium">{user.email}</span>
                <span className="block text-xs text-muted-foreground">{roleLabels[user.role]}</span>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={async () => { await signOut(); router.replace("/login/"); }}>
                <LogOut /> Sign out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>
    </header>
  );
}
