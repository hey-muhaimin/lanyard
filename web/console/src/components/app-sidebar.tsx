"use client";

// Shell follows shadcn's dashboard blocks: collapsible sidebar, header with trigger, inset content.
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Activity, Bot, ChevronsUpDown, LayoutDashboard, LogOut, Plug, Scale, ScrollText, Settings, ShieldCheck, type LucideIcon } from "lucide-react";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent, SidebarHeader, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarRail } from "@/components/ui/sidebar";
import { can, roleLabels, type Permission } from "@/lib/roles";
import { useSession, useUser } from "@/lib/session";

interface NavItem { title: string; href: string; icon: LucideIcon; permission?: Permission }

export const navItems: NavItem[] = [
  { title: "Overview", href: "/overview/", icon: LayoutDashboard },
  { title: "Agents", href: "/agents/", icon: Bot, permission: "agents.read" },
  { title: "Approvals", href: "/approvals/", icon: ShieldCheck, permission: "approvals.read" },
  { title: "Activity", href: "/activity/", icon: Activity, permission: "events.read" },
  { title: "Connectors", href: "/connectors/", icon: Plug },
  { title: "Policies", href: "/policies/", icon: Scale },
  { title: "Audit and reports", href: "/audit/", icon: ScrollText },
  { title: "Settings", href: "/settings/", icon: Settings },
];

export function AppSidebar() {
  const pathname = usePathname();
  const user = useUser();
  const items = navItems.filter((item) => !item.permission || can(user?.role, item.permission));

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" asChild>
              <Link href="/overview/">
                <span className="flex size-8 items-center justify-center bg-sidebar-primary font-mono text-sm text-sidebar-primary-foreground">L</span>
                <span className="grid text-left leading-tight">
                  <span className="font-semibold">Lanyard</span>
                  <span className="truncate font-mono text-xs text-muted-foreground">{user?.tenant_id}</span>
                </span>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {items.map(({ title, href, icon: Icon }) => (
                <SidebarMenuItem key={href}>
                  <SidebarMenuButton asChild isActive={pathname === href || pathname === href.slice(0, -1)} tooltip={title}>
                    <Link href={href}>
                      <Icon />
                      <span>{title}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter>
        <NavUser />
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}

function NavUser() {
  const user = useUser();
  const { signOut } = useSession();
  const router = useRouter();
  if (!user) return null;
  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton size="lg" tooltip={user.email}>
              <Avatar className="size-8"><AvatarFallback>{user.email.slice(0, 2).toUpperCase()}</AvatarFallback></Avatar>
              <span className="grid flex-1 text-left leading-tight">
                <span className="truncate text-sm font-medium">{user.email}</span>
                <span className="truncate text-xs text-muted-foreground">{roleLabels[user.role]}</span>
              </span>
              <ChevronsUpDown className="ml-auto size-4" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent side="top" align="start" className="min-w-56">
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
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
