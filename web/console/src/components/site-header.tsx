"use client";

import { usePathname } from "next/navigation";
import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { navItems } from "@/components/app-sidebar";

export function SiteHeader() {
  const pathname = usePathname();
  const title = navItems.find((item) => item.href === pathname || item.href.slice(0, -1) === pathname)?.title ?? "Lanyard";
  return (
    <header className="flex h-14 shrink-0 items-center gap-2 border-b px-4">
      <SidebarTrigger className="-ml-1" />
      <Separator orientation="vertical" className="mr-2 data-[orientation=vertical]:h-4" />
      <h1 className="text-base font-medium">{title}</h1>
    </header>
  );
}
