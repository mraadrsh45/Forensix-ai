"use client";
import AppLayout from "@/components/AppLayout";
import { use, useState } from "react";
import { ArrowLeft, Shield, AlertTriangle, Clock, User, Tag, FileText, Download, Activity, CheckCircle, Database, Lock, Eye } from "lucide-react";

const MOCK_CASES_MAP: Record<string, any> = {
  "CASE-2401": {
    id: "CASE-2401",
    title: "Ransomware Incident – Finance Department",
    status: "Active",
    priority: "Critical",
    type: "Malware",
    investigator: "Alice Chen",
    created: "2025-07-19",
    description: "Suspicious PowerShell execution detected on Host FIN-W10-092 followed by file encryption and .locked extension appending.",
    artifacts: [
      { name: "invoice_994.exe", type: "Malware Binary", sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", threat: "LockBit 3.0" },
      { name: "mem_dump_fin092.raw", type: "Memory Dump", size: "4.2 GB", threat: "LSASS Injection" },
      { name: "c2_network.pcap", type: "Network Capture", size: "128 MB", threat: "185.220.101.5:443 C2" }
    ],
    timeline: [
      { time: "2025-07-19 14:22:10 UTC", event: "User executed phishing email attachment invoice_994.exe" },
      { time: "2025-07-19 14:22:15 UTC", event: "PowerShell spawn with encoded payload to bypass ExecutionPolicy" },
      { time: "2025-07-19 14:23:01 UTC", event: "C2 beacon established to 185.220.101.5" },
      { time: "2025-07-19 14:25:40 UTC", event: "Shadow copies deleted via vssadmin.exe delete shadows /all /quiet" },
      { time: "2025-07-19 14:26:00 UTC", event: "Mass encryption initiated across local drives" }
    ]
  }
};

export default function CaseDetailsPage({ params }: { params: Promise<{ id: string }> }) {
  const resolvedParams = use(params);
  const caseId = resolvedParams.id;
  const [activeTab, setActiveTab] = useState<"overview" | "artifacts" | "timeline">("overview");

  const caseData = MOCK_CASES_MAP[caseId] || {
    id: caseId,
    title: `Investigation Case ${caseId}`,
    status: "Active",
    priority: "High",
    type: "Digital Forensics",
    investigator: "Admin User",
    created: "2025-07-20",
    description: `Detailed digital evidence analysis and forensic investigation report for case identifier ${caseId}.`,
    artifacts: [
      { name: "evidence_artifact_01.bin", type: "File Artifact", sha256: "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0", threat: "Suspicious Activity" },
      { name: "network_log.pcap", type: "Network Log", size: "45 MB", threat: "Unusual Traffic" }
    ],
    timeline: [
      { time: "2025-07-20 09:00:00 UTC", event: "Case registered into ForensiX AI pipeline." },
      { time: "2025-07-20 09:15:30 UTC", event: "Automated indicator extraction completed." }
    ]
  };

  return (
    <AppLayout title={`Case ${caseId}`}>
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Header navigation */}
        <div className="flex items-center justify-between">
          <a href="/cases" className="btn-ghost text-xs flex items-center gap-1 text-slate-400 hover:text-white">
            <ArrowLeft className="w-4 h-4" /> Back to Cases
          </a>
          <div className="flex items-center gap-2">
            <span className="badge risk-critical">{caseData.priority} Priority</span>
            <span className="badge bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">{caseData.status}</span>
          </div>
        </div>

        {/* Case Info banner */}
        <div className="stat-card space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <div className="text-xs font-mono text-cyan-400 mb-1">{caseData.id}</div>
              <h1 className="text-2xl font-bold text-white">{caseData.title}</h1>
            </div>
            <div className="flex items-center gap-3">
              <a href="/reports" className="btn-primary text-xs flex items-center gap-1.5">
                <Download className="w-3.5 h-3.5" /> Export PDF Report
              </a>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
            <div>
              <span className="text-slate-500 block mb-0.5">Investigator</span>
              <span className="text-slate-200 font-medium">{caseData.investigator}</span>
            </div>
            <div>
              <span className="text-slate-500 block mb-0.5">Case Category</span>
              <span className="text-slate-200 font-medium">{caseData.type}</span>
            </div>
            <div>
              <span className="text-slate-500 block mb-0.5">Created Date</span>
              <span className="text-slate-200 font-medium">{caseData.created}</span>
            </div>
            <div>
              <span className="text-slate-500 block mb-0.5">Evidence Items</span>
              <span className="text-cyan-400 font-medium">{caseData.artifacts.length} artifacts</span>
            </div>
          </div>
        </div>

        {/* Tab navigation */}
        <div className="flex gap-2 border-b border-slate-800 pb-1">
          {[
            { id: "overview", label: "Overview & Description", icon: Shield },
            { id: "artifacts", label: "Evidence & Artifacts", icon: Database },
            { id: "timeline", label: "Incident Timeline", icon: Clock },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-t-lg transition-colors ${
                activeTab === tab.id
                  ? "bg-slate-800 text-cyan-400 border-b-2 border-cyan-400"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
              }`}
            >
              <tab.icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === "overview" && (
          <div className="space-y-4">
            <div className="stat-card">
              <h3 className="text-sm font-semibold text-slate-200 mb-2 flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyan-400" /> Summary & Initial Findings
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed">{caseData.description}</p>
            </div>

            <div className="stat-card">
              <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-emerald-400" /> Recommended Action Items
              </h3>
              <ul className="space-y-2 text-xs text-slate-300">
                <li className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                  Isolate affected host machine from domain network.
                </li>
                <li className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                  Revoke active session tokens for compromised user account.
                </li>
                <li className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                  Block C2 IP addresses in gateway firewall policy.
                </li>
              </ul>
            </div>
          </div>
        )}

        {activeTab === "artifacts" && (
          <div className="stat-card overflow-hidden">
            <h3 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-400" /> Case Evidence & Forensic Artifacts
            </h3>
            <table className="forensic-table">
              <thead>
                <tr>
                  <th>Artifact Name</th><th>Category</th><th>Threat Match</th><th>Details</th>
                </tr>
              </thead>
              <tbody>
                {caseData.artifacts.map((art: any, i: number) => (
                  <tr key={i}>
                    <td className="font-mono text-xs text-cyan-400">{art.name}</td>
                    <td><span className="badge bg-white/5 text-slate-300">{art.type}</span></td>
                    <td><span className="badge risk-critical">{art.threat}</span></td>
                    <td className="text-xs text-slate-400 font-mono">{art.sha256 || art.size}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === "timeline" && (
          <div className="stat-card space-y-4">
            <h3 className="text-sm font-semibold text-slate-200 mb-2 flex items-center gap-2">
              <Clock className="w-4 h-4 text-cyan-400" /> Chronological Event Log
            </h3>
            <div className="space-y-3 relative pl-4 border-l border-cyan-500/30">
              {caseData.timeline.map((evt: any, i: number) => (
                <div key={i} className="relative">
                  <span className="absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full bg-cyan-400 border border-slate-950"></span>
                  <div className="text-[11px] font-mono text-cyan-400">{evt.time}</div>
                  <div className="text-xs text-slate-200 mt-0.5">{evt.event}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </AppLayout>
  );
}
