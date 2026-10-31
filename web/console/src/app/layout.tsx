import type { Metadata } from "next";
import localFont from "next/font/local";
import { Toaster } from "@/components/ui/sonner";
import { SessionProvider } from "@/lib/session";
import "./globals.css";

const inter = localFont({
  src: "../public/fonts/Inter-Variable.woff2",
  variable: "--font-inter",
  display: "swap",
});
const plexMono = localFont({
  src: "../public/fonts/IBMPlexMono-Variable.woff2",
  weight: "400 500",
  variable: "--font-plex-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: { default: "Lanyard", template: "%s · Lanyard" },
  description: "Task-scoped identity, secrets, and audit for AI agents.",
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
