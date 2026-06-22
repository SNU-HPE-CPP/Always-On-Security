import { Metadata } from "next";
import "./globals.css";
import { Providers } from "@/components/query-provider";
import { AppShell } from "@/components/layout/app-shell";
import { Toaster } from "sonner";

export const metadata: Metadata = {
  title: "Always On Security Dashboard",
  description: "Always On Security Dashboard",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <Providers>
          <AppShell>{children}</AppShell>

          <Toaster richColors />
        </Providers>
      </body>
    </html>
  );
}
