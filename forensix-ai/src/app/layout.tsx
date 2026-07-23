import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });

export const metadata: Metadata = {
  title: "ForensiX AI – Enterprise Digital Forensics Platform",
  description: "AI-powered Digital Forensics & Threat Intelligence Platform for SOC teams, investigators, and cybersecurity analysts.",
  keywords: ["digital forensics", "threat intelligence", "cybersecurity", "malware analysis", "OSINT"],
  authors: [{ name: "ForensiX AI" }],
  openGraph: {
    title: "ForensiX AI",
    description: "Enterprise Digital Forensics & Threat Intelligence Platform",
    type: "website",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`dark ${inter.variable}`}>
      <body className="font-sans antialiased">
        {children}
      </body>
    </html>
  );
}
