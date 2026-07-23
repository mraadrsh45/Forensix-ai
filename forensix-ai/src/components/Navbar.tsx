"use client";
import { Bell, Search, Menu, Shield, ChevronDown } from "lucide-react";
import { useState, useEffect, useRef } from "react";

interface NavbarProps {
  onMenuClick: () => void;
  title?: string;
}

const ALERTS = [
  { type: "critical", msg: "Malicious URL detected: phish-bank.tk", time: "2m ago" },
  { type: "high", msg: "Suspicious IP 185.234.219.45 flagged", time: "8m ago" },
  { type: "medium", msg: "New IOC added to threat feed", time: "15m ago" },
];

export default function Navbar({ onMenuClick, title }: NavbarProps) {
  const [showAlerts, setShowAlerts] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const controlsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (controlsRef.current && !controlsRef.current.contains(e.target as Node)) {
        setShowAlerts(false);
        setShowProfile(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  return (
    <header className="h-16 border-b border-white/[0.06] bg-[#080e1a]/90 backdrop-blur flex items-center px-4 gap-4 sticky top-0 z-10">
      <button onClick={onMenuClick} className="lg:hidden text-slate-400 hover:text-white">
        <Menu className="w-5 h-5" />
      </button>

      {title && (
        <h1 className="text-sm font-semibold text-slate-200 hidden sm:block">{title}</h1>
      )}

      {/* Search */}
      <div className="flex-1 max-w-md ml-2">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search IOCs, domains, IPs, cases..."
            className="forensic-input pl-9 py-2 text-sm h-9"
          />
        </div>
      </div>

      <div ref={controlsRef} className="ml-auto flex items-center gap-2">
        {/* Threat level indicator */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20">
          <div className="pulse-dot pulse-dot-red w-2 h-2" />
          <span className="text-xs text-red-400 font-medium">THREAT: HIGH</span>
        </div>

        {/* Alerts bell */}
        <div className="relative">
          <button
            onClick={() => { setShowAlerts(!showAlerts); setShowProfile(false); }}
            className="relative w-9 h-9 flex items-center justify-center rounded-lg hover:bg-white/5 text-slate-400 hover:text-white transition-colors"
          >
            <Bell className="w-4.5 h-4.5" />
            <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full border border-[#080e1a]" />
          </button>
          {showAlerts && (
            <div className="absolute right-0 top-11 w-80 glass-strong rounded-xl shadow-2xl border border-white/10 overflow-hidden z-50">
              <div className="px-4 py-3 border-b border-white/[0.06] flex items-center justify-between">
                <span className="text-sm font-semibold text-slate-200">Security Alerts</span>
                <span className="badge risk-critical">{ALERTS.length} Active</span>
              </div>
              {ALERTS.map((a, i) => (
                <div key={i} className="px-4 py-3 border-b border-white/[0.04] hover:bg-white/[0.03] cursor-pointer">
                  <div className="flex items-start gap-2">
                    <div className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${
                      a.type === "critical" ? "bg-red-400" : a.type === "high" ? "bg-orange-400" : "bg-yellow-400"
                    }`} />
                    <div>
                      <p className="text-xs text-slate-300">{a.msg}</p>
                      <p className="text-[10px] text-slate-500 mt-0.5">{a.time}</p>
                    </div>
                  </div>
                </div>
              ))}
              <div className="px-4 py-2 text-center">
                <button className="text-xs text-cyan-400 hover:text-cyan-300">View all alerts</button>
              </div>
            </div>
          )}
        </div>

        {/* Profile */}
        <div className="relative">
          <button
            onClick={() => { setShowProfile(!showProfile); setShowAlerts(false); }}
            className="flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-white/5 transition-colors"
          >
            <div className="w-7 h-7 rounded-full bg-gradient-to-br from-cyan-500 to-violet-600 flex items-center justify-center text-white font-bold text-xs">A</div>
            <div className="hidden sm:block text-left">
              <div className="text-xs font-medium text-slate-200">Admin</div>
              <div className="text-[10px] text-slate-500">Senior Analyst</div>
            </div>
            <ChevronDown className="w-3 h-3 text-slate-500" />
          </button>
          {showProfile && (
            <div className="absolute right-0 top-11 w-48 glass-strong rounded-xl shadow-2xl border border-white/10 overflow-hidden z-50">
              {["Profile", "API Keys", "Audit Log", "Sign Out"].map((item) => (
                <button key={item} className="w-full text-left px-4 py-2.5 text-sm text-slate-300 hover:bg-white/[0.05] hover:text-white transition-colors">
                  {item}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
