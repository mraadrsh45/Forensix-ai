"use client";
import AppLayout from "@/components/AppLayout";
import { useState } from "react";
import { Plus, Search, Filter, FolderOpen, Clock, AlertTriangle, Shield, User, Tag, ChevronRight } from "lucide-react";

const CASES = [
  { id: "CASE-2401", title: "Ransomware Incident – Finance Department", status: "Active", priority: "Critical", type: "Malware", investigator: "Alice Chen", created: "2025-07-19", evidence: 14 },
  { id: "CASE-2400", title: "Phishing Campaign – Executive Spear Attack", status: "Active", priority: "High", type: "Email", investigator: "Bob Smith", created: "2025-07-18", evidence: 8 },
  { id: "CASE-2399", title: "Suspicious Network Traffic – DMZ Zone", status: "Review", priority: "Medium", type: "Network", investigator: "Carol Davis", created: "2025-07-17", evidence: 22 },
  { id: "CASE-2398", title: "Data Exfiltration Attempt via USB", status: "Closed", priority: "High", type: "Insider", investigator: "David Lee", created: "2025-07-15", evidence: 35 },
  { id: "CASE-2397", title: "Malicious PDF – HR Payroll Scam", status: "Closed", priority: "Medium", type: "File", investigator: "Eve Martinez", created: "2025-07-14", evidence: 6 },
  { id: "CASE-2396", title: "Brute Force Attack – VPN Gateway", status: "Active", priority: "High", type: "Network", investigator: "Frank Wu", created: "2025-07-13", evidence: 18 },
];

const priorityColor: Record<string, string> = {
  Critical: "risk-critical", High: "risk-high", Medium: "risk-medium", Low: "risk-low",
};
const statusColor: Record<string, string> = {
  Active: "risk-critical", Review: "risk-medium", Closed: "risk-safe",
};

export default function Cases() {
  const [search, setSearch] = useState("");
  const [showNew, setShowNew] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [cases, setCases] = useState(CASES);

  const filtered = cases.filter(c =>
    c.title.toLowerCase().includes(search.toLowerCase()) ||
    c.id.toLowerCase().includes(search.toLowerCase())
  );

  function createCase() {
    if (!newTitle.trim()) return;
    const c = {
      id: `CASE-${2400 + cases.length + 2}`,
      title: newTitle,
      status: "Active",
      priority: "High",
      type: "General",
      investigator: "Admin User",
      created: new Date().toISOString().split("T")[0],
      evidence: 0,
    };
    setCases([c, ...cases]);
    setNewTitle(""); setShowNew(false);
  }

  return (
    <AppLayout title="Case Management">
      <div className="max-w-6xl mx-auto space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-2xl font-bold text-slate-100 mb-1">Investigation Cases</h2>
            <p className="text-sm text-slate-500">{cases.filter(c => c.status === "Active").length} active · {cases.length} total</p>
          </div>
          <button onClick={() => setShowNew(true)} className="btn-primary">
            <Plus className="w-4 h-4" />New Case
          </button>
        </div>

        {showNew && (
          <div className="stat-card border border-cyan-500/20">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">Create New Investigation Case</h3>
            <div className="flex gap-3">
              <input value={newTitle} onChange={e => setNewTitle(e.target.value)} onKeyDown={e => e.key === "Enter" && createCase()}
                placeholder="Case title (e.g. Suspicious Login Activity – AWS Console)"
                className="forensic-input flex-1" />
              <button onClick={createCase} className="btn-primary">Create</button>
              <button onClick={() => setShowNew(false)} className="btn-ghost">Cancel</button>
            </div>
          </div>
        )}

        {/* Stats row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total Cases", value: cases.length, icon: FolderOpen, color: "cyan" },
            { label: "Active", value: cases.filter(c => c.status === "Active").length, icon: AlertTriangle, color: "red" },
            { label: "Under Review", value: cases.filter(c => c.status === "Review").length, icon: Clock, color: "yellow" },
            { label: "Closed", value: cases.filter(c => c.status === "Closed").length, icon: Shield, color: "emerald" },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="stat-card flex items-center gap-3">
              <div className={`w-9 h-9 rounded-lg bg-${color}-500/10 border border-${color}-500/20 flex items-center justify-center`}>
                <Icon className={`w-4 h-4 text-${color}-400`} />
              </div>
              <div>
                <div className="text-xl font-bold text-white">{value}</div>
                <div className="text-xs text-slate-500">{label}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search cases by ID, title, or type..."
            className="forensic-input pl-9" />
        </div>

        {/* Cases table */}
        <div className="stat-card overflow-hidden">
          <table className="forensic-table">
            <thead>
              <tr>
                <th>Case ID</th><th>Title</th><th>Type</th>
                <th>Priority</th><th>Status</th><th>Investigator</th>
                <th>Evidence</th><th>Created</th><th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(c => (
                <tr key={c.id} className="cursor-pointer">
                  <td className="font-mono text-cyan-400 text-xs">{c.id}</td>
                  <td className="max-w-[220px]">
                    <div className="text-slate-200 text-xs font-medium truncate">{c.title}</div>
                  </td>
                  <td><span className="badge bg-white/5 text-slate-400">{c.type}</span></td>
                  <td><span className={`badge ${priorityColor[c.priority]}`}>{c.priority}</span></td>
                  <td><span className={`badge ${statusColor[c.status]}`}>{c.status}</span></td>
                  <td>
                    <div className="flex items-center gap-1.5 text-xs">
                      <div className="w-5 h-5 rounded-full bg-gradient-to-br from-cyan-500 to-violet-600 flex items-center justify-center text-white text-[9px] font-bold">
                        {c.investigator.split(" ").map(w => w[0]).join("")}
                      </div>
                      <span className="text-slate-400">{c.investigator.split(" ")[0]}</span>
                    </div>
                  </td>
                  <td className="text-xs text-slate-400">{c.evidence} items</td>
                  <td className="text-xs text-slate-500">{c.created}</td>
                  <td>
                    <a href={`/cases/${c.id}`} className="text-slate-500 hover:text-cyan-400">
                      <ChevronRight className="w-4 h-4" />
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length === 0 && (
            <div className="text-center py-10 text-slate-500 text-sm">No cases found matching "{search}"</div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
