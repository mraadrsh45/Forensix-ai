"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield, LayoutDashboard, FolderOpen, Globe, Network, Cpu,
  Mail, FileText, Bug, Wifi, Brain, Smartphone, AlertTriangle,
  Bot, FileBarChart, Settings, ChevronRight, Zap, X, Layers, Share2
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV = [
  { label: "MAIN", items: [
    { href: "/dashboard", icon: LayoutDashboard, label: "Dashboard" },
    { href: "/pipeline", icon: Layers, label: "Data Pipeline" },
    { href: "/cases", icon: FolderOpen, label: "Case Management" },
  ]},

  { label: "INTELLIGENCE", items: [
    { href: "/website-intel", icon: Globe, label: "Website Intelligence" },
    { href: "/osint", icon: Share2, label: "OSINT Module" },
    { href: "/domain-intel", icon: Network, label: "Domain & DNS" },
    { href: "/ip-intel", icon: Cpu, label: "IP Intelligence" },
    { href: "/threat-intel", icon: AlertTriangle, label: "Threat Intelligence" },
    { href: "/global-threat-center", icon: Shield, label: "Global Threat Intelligence Center" },
  ]},

  { label: "FORENSICS", items: [
    { href: "/email-forensics", icon: Mail, label: "Email Forensics" },
    { href: "/file-forensics", icon: FileText, label: "File Forensics" },
    { href: "/malware-analysis", icon: Bug, label: "Malware Analysis" },
    { href: "/network-forensics", icon: Wifi, label: "Network Forensics" },
    { href: "/memory-forensics", icon: Brain, label: "Memory Forensics" },
    { href: "/mobile-forensics", icon: Smartphone, label: "Mobile Forensics" },
  ]},
  { label: "AI & REPORTS", items: [
    { href: "/ai-assistant", icon: Bot, label: "AI Assistant" },
    { href: "/reports", icon: FileBarChart, label: "Reports" },
  ]},
  { label: "SYSTEM", items: [
    { href: "/settings", icon: Settings, label: "Settings" },
  ]},
];

interface SidebarProps {
  open: boolean;
  onClose?: () => void;
}

export default function Sidebar({ open, onClose }: SidebarProps) {
  const pathname = usePathname();

  return (
    <>
      {/* Mobile overlay */}
      {open && (
        <div className="fixed inset-0 z-20 bg-black/60 lg:hidden" onClick={onClose} />
      )}

      <aside className={cn(
        "fixed top-0 left-0 h-full z-30 flex flex-col transition-transform duration-300",
        "bg-[#080e1a] border-r border-white/[0.06]",
        "w-[260px]",
        open ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
      )}>
        {/* Logo */}
        <div className="flex items-center justify-between px-5 py-5 border-b border-white/[0.06]">
          <Link href="/dashboard" className="flex items-center gap-3 group">
            <div className="relative">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
                <Shield className="w-4 h-4 text-white" />
              </div>
              <div className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-emerald-400 rounded-full border border-[#080e1a] animate-pulse" />
            </div>
            <div>
              <span className="text-white font-bold text-lg tracking-tight leading-none">ForensiX</span>
              <span className="text-cyan-400 font-bold text-lg tracking-tight leading-none"> AI</span>
              <div className="text-[10px] text-slate-500 leading-none mt-0.5 tracking-widest uppercase">Digital Forensics</div>
            </div>
          </Link>
          <button onClick={onClose} className="lg:hidden text-slate-500 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Status bar */}
        <div className="mx-4 my-3 px-3 py-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center gap-2">
          <div className="pulse-dot" />
          <span className="text-xs text-emerald-400 font-medium">Systems Operational</span>
          <Zap className="w-3 h-3 text-emerald-400 ml-auto" />
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto px-3 pb-4 space-y-4">
          {NAV.map((section) => (
            <div key={section.label}>
              <p className="text-[10px] font-bold text-slate-600 tracking-widest px-3 mb-1 mt-2">
                {section.label}
              </p>
              {section.items.map(({ href, icon: Icon, label }) => {
                const active = pathname === href;
                return (
                  <Link key={href} href={href} className={cn("sidebar-item", active && "active")} onClick={onClose}>
                    <Icon className="w-4 h-4 flex-shrink-0" />
                    <span className="flex-1">{label}</span>
                    {active && <ChevronRight className="w-3 h-3 opacity-50" />}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>

        {/* User footer */}
        <div className="border-t border-white/[0.06] p-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-500 to-violet-600 flex items-center justify-center text-white font-bold text-sm">
              A
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-slate-200 truncate">Admin User</div>
              <div className="text-xs text-slate-500 truncate">Senior Analyst</div>
            </div>
            <div className="w-2 h-2 bg-emerald-400 rounded-full" />
          </div>
        </div>
      </aside>
    </>
  );
}
