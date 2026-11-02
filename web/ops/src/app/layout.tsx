import type { Metadata } from "next";
import { Toaster } from "@/components/ui/sonner";
import { SessionProvider } from "@/lib/session";
import "./globals.css";

// Placeholder font objects – real fonts can be added later via next/font/local.
const inter = { variable: "--font-inter" } as any;
const plexMono = { variable: "--font-plex-mono" } as any;


export const metadata: Metadata = {
  title: { default: "Lanyard Ops", template: "%s · Lanyard Ops" },
  description: "Internal platform operations. Staff only.",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${plexMono.variable}`}>
      <body>
        <SessionProvider>{children}</SessionProvider>
        <Toaster position="bottom-right" />
      </body>
    </html>
  );
}
