import type { Metadata } from "next";
import { Toaster } from "@/components/ui/sonner";
import { SessionProvider } from "@/lib/session";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "Lanyard", template: "%s · Lanyard" },
  description: "Task-scoped identity, secrets, and audit for AI agents.",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <SessionProvider>{children}</SessionProvider>
        <Toaster position="bottom-right" />
      </body>
    </html>
  );
}
