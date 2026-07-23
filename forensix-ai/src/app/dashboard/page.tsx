"use client";
import AppLayout from "@/components/AppLayout";
import {
  Shield, AlertTriangle, Globe, FileText, Bug, Network,
  TrendingUp, Eye, Clock, Zap, ArrowUpRight, Activity, Database
} from "lucide-react";
import { useEffect, useState } from "react";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell
} from "recharts";

const THREAT_TREND = [
  { t: "00:00", threats: 12, blocked: 10 },
  { t: "04:00", threats: 28, blocked: 25 },
  { t: "08:00", threats: 65, blocked: 58 },
  { t: "12:00", threats: 142, blocked: 130 },
  { t: "16:00", threats: 98, blocked: 90 },
  { t: "20:00", threats: 77, blocked: 72 },
  { t: "Now", threats: 45, blocked: 43 },
];

const IOC_TYPES = [
  { name: "Malicious URLs", value: 342, color: "#ef4444" },
  { name: "Suspicious IPs", value: 198, color: "#f97316" },
  { name: "Malware Hashes", value: 156, color: "#8b5cf6" },
  { name: "Phishing Domains", value: 124, color: "#eab308" },
  { name: "Email IOCs", value: 89, color: "#06b6d4" },
];

const RECENT_CASES = [
  { id: "CASE-2401", title: "Ransomware Incident – Finance Dept", status: "Active", risk: 95, type: "Malware" },
  { id: "CASE-2400", title: "Phishing Campaign – Executive Spear", status: "Active", risk: 82, type: "Email" },
  { id: "CASE-2399", title: "Suspicious Network Traffic – DMZ", status: "Review", risk: 67, type: "Network" },
  { id: "CASE-2398", title: "Data Exfiltration Attempt", status: "Closed", risk: 91, type: "Network" },
  { id: "CASE-2397", title: "Malicious PDF – HR Department", status: "Closed", risk: 74, type: "File" },
];

const LIVE_FEED = [
  { time: "now", type: "BLOCK", msg: "Malicious URL blocked: http://login-secure-bank.tk" },
  { time: "1m", type: "ALERT", msg: "C2 communication detected from 185.234.219.45" },
  { time: "3m", type: "IOC", msg: "New malware hash added: SHA256:3a4f9b..." },
  { time: "5m", type: "CASE", msg: "Case CASE-2401 updated by analyst@forensix.ai" },
  { time: "8m", type: "BLOCK", msg: "Phishing domain flagged: paypa1-secure.com" },
  { time: "12m", type: "ALERT", msg: "Memory anomaly detected in process svchost.exe" },
];

const STATS = [
  { label: "Active Cases", value: "24", delta: "+3 today", icon: Shield, color: "cyan", danger: false },
  { label: "Threats Detected", value: "1,847", delta: "+142 today", icon: AlertTriangle, color: "red", danger: true },
  { label: "IOCs Tracked", value: "9,234", delta: "+89 new", icon: Eye, color: "violet", danger: false },
  { label: "Analyses Today", value: "328", delta: "+56 vs yesterday", icon: Activity, color: "emerald", danger: false },
];

function LiveCounter({ target }: { target: number }) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    const step = Math.ceil(target / 40);
    const t = setInterval(() => setVal(v => Math.min(v + step, target)), 30);
    return () => clearInterval(t);
  }, [target]);
  return <>{val.toLocaleString()}</>;
}

const RISK_LABEL: Record<number, string> = {};
function riskBadge(score: number) {
  if (score >= 80) return "risk-critical";
  if (score >= 60) return "risk-high";
  if (score >= 40) return "risk-medium";
  return "risk-low";
}
function riskLabel(score: number) {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 40) return "Medium";
  return "Low";
}

export default function Dashboard() {
  const [feedIdx, setFeedIdx] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setFeedIdx(i => (i + 1) % LIVE_FEED.length), 3000);
    return () => clearInterval(t);
  }, []);

  return (
    <AppLayout title="SOC Dashboard">
      {/* Live threat ticker */}
      <div className="mb-5 px-4 py-2.5 rounded-lg bg-red-500/8 border border-red-500/20 flex items-center gap-3 overflow-hidden">
        <div className="flex items-center gap-2 flex-shrink-0">
          <div className="pulse-dot pulse-dot-red w-2 h-2" />
          <span className="text-xs font-bold text-red-400 tracking-widest">LIVE FEED</span>
        </div>
        <div className="h-4 w-px bg-red-500/30" />
        <div className="text-xs text-slate-300 truncate transition-all duration-500">
          <span className={`badge mr-2 ${
            LIVE_FEED[feedIdx].type === "BLOCK" ? "risk-critical" :
            LIVE_FEED[feedIdx].type === "ALERT" ? "risk-high" :
            LIVE_FEED[feedIdx].type === "IOC" ? "risk-medium" : "risk-safe"
          }`}>{LIVE_FEED[feedIdx].type}</span>
          {LIVE_FEED[feedIdx].msg}
        </div>
        <span className="ml-auto text-[10px] text-slate-600 flex-shrink-0">{LIVE_FEED[feedIdx].time} ago</span>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {STATS.map(({ label, value, delta, icon: Icon, color, danger }) => (
          <div key={label} className={`stat-card hover:border-${color}-500/20`}>
            <div className="flex items-start justify-between mb-3">
              <div className={`w-9 h-9 rounded-lg bg-${color}-500/10 border border-${color}-500/20 flex items-center justify-center`}>
                <Icon className={`w-4 h-4 text-${color}-400`} />
              </div>
              <ArrowUpRight className={`w-3.5 h-3.5 ${danger ? "text-red-400" : "text-emerald-400"}`} />
            </div>
            <div className="text-2xl font-black text-white mb-0.5">
              <LiveCounter target={parseInt(value.replace(/,/g, ""))} />
            </div>
            <div className="text-xs text-slate-500">{label}</div>
            <div className={`text-[10px] mt-1 ${danger ? "text-red-400" : "text-emerald-400"}`}>{delta}</div>
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div className="grid lg:grid-cols-3 gap-4 mb-6">
        {/* Threat trend */}
        <div className="lg:col-span-2 stat-card">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Threat Activity (24h)</h3>
              <p className="text-xs text-slate-500">Detected vs blocked threats</p>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-red-400" />Detected</div>
              <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-emerald-400" />Blocked</div>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={THREAT_TREND}>
              <defs>
                <linearGradient id="threats" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="blocked" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="t" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid rgba(148,163,184,0.1)", borderRadius: 8, fontSize: 12 }} />
              <Area type="monotone" dataKey="threats" stroke="#ef4444" fill="url(#threats)" strokeWidth={2} />
              <Area type="monotone" dataKey="blocked" stroke="#10b981" fill="url(#blocked)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* IOC breakdown */}
        <div className="stat-card">
          <h3 className="text-sm font-semibold text-slate-200 mb-1">IOC Breakdown</h3>
          <p className="text-xs text-slate-500 mb-4">By category</p>
          <ResponsiveContainer width="100%" height={160}>
            <PieChart>
              <Pie data={IOC_TYPES} cx="50%" cy="50%" innerRadius={45} outerRadius={70}
                dataKey="value" strokeWidth={0}>
                {IOC_TYPES.map((e, i) => <Cell key={i} fill={e.color} />)}
              </Pie>
              <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid rgba(148,163,184,0.1)", borderRadius: 8, fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="space-y-1.5 mt-2">
            {IOC_TYPES.map(({ name, value, color }) => (
              <div key={name} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full" style={{ background: color }} />
                  <span className="text-slate-400">{name}</span>
                </div>
                <span className="text-slate-300 font-medium">{value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Cases + Feed */}
      <div className="grid lg:grid-cols-2 gap-4">
        {/* Recent cases */}
        <div className="stat-card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-200">Recent Cases</h3>
            <a href="/cases" className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1">
              View all <ArrowUpRight className="w-3 h-3" />
            </a>
          </div>
          <table className="forensic-table">
            <thead>
              <tr>
                <th>Case</th><th>Type</th><th>Risk</th><th>Status</th>
              </tr>
            </thead>
            <tbody>
              {RECENT_CASES.map(({ id, title, status, risk, type }) => (
                <tr key={id} className="cursor-pointer">
                  <td>
                    <div className="text-xs font-medium text-cyan-400">{id}</div>
                    <div className="text-xs text-slate-500 truncate max-w-[160px]">{title}</div>
                  </td>
                  <td><span className="badge bg-white/5 text-slate-400">{type}</span></td>
                  <td>
                    <span className={`badge ${riskBadge(risk)}`}>{riskLabel(risk)}</span>
                  </td>
                  <td>
                    <span className={`badge ${status === "Active" ? "risk-critical" : status === "Review" ? "risk-medium" : "risk-safe"}`}>
                      {status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Live event log */}
        <div className="stat-card scan-line">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-200">Live Event Log</h3>
            <div className="flex items-center gap-2">
              <div className="pulse-dot w-1.5 h-1.5" />
              <span className="text-[10px] text-emerald-400">LIVE</span>
            </div>
          </div>
          <div className="space-y-2 font-mono text-xs">
            {LIVE_FEED.map((e, i) => (
              <div key={i} className={`flex items-start gap-2 p-2 rounded-lg transition-colors ${i === 0 ? "bg-cyan-500/5 border border-cyan-500/10" : ""}`}>
                <span className="text-slate-600 flex-shrink-0 w-8">{e.time}</span>
                <span className={`badge flex-shrink-0 ${
                  e.type === "BLOCK" ? "risk-critical" :
                  e.type === "ALERT" ? "risk-high" :
                  e.type === "IOC" ? "risk-medium" : "risk-safe"
                }`}>{e.type}</span>
                <span className="text-slate-400 leading-relaxed">{e.msg}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Module quick-access */}
      <div className="mt-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { href: "/website-intel", icon: Globe, label: "Website Intel", color: "cyan" },
          { href: "/email-forensics", icon: FileText, label: "Email Forensics", color: "blue" },
          { href: "/malware-analysis", icon: Bug, label: "Malware", color: "red" },
          { href: "/network-forensics", icon: Network, label: "Network", color: "violet" },
          { href: "/threat-intel", icon: AlertTriangle, label: "Threat Intel", color: "orange" },
          { href: "/ai-assistant", icon: Zap, label: "AI Assistant", color: "emerald" },
        ].map(({ href, icon: Icon, label, color }) => (
          <a key={href} href={href}
            className="stat-card flex flex-col items-center gap-2 py-4 hover:border-cyan-500/20 text-center group">
            <div className={`w-8 h-8 rounded-lg bg-${color}-500/10 flex items-center justify-center group-hover:bg-${color}-500/20 transition-colors`}>
              <Icon className={`w-4 h-4 text-${color}-400`} />
            </div>
            <span className="text-xs text-slate-400 group-hover:text-slate-200 transition-colors">{label}</span>
          </a>
        ))}
      </div>
    </AppLayout>
  );
}
