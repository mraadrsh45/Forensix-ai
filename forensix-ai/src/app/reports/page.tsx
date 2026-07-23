"use client";

import AppLayout from "@/components/AppLayout";
import { useState } from "react";
import {
  FileBarChart, Download, Eye, Clock, Shield, AlertTriangle, FileText,
  User, CheckCircle2, RefreshCw, ArrowRight, Layers, Sparkles, FileDown
} from "lucide-react";

const REPORT_TEMPLATES = [
  { id: "master", label: "Master Forensic Pipeline Report", icon: "📑", desc: "Full 8-stage correlation, timeline, MITRE, AI summary & PDF", color: "cyan" },
  { id: "website", label: "Website Investigation Report", icon: "🌐", desc: "URL reputation, SSL, DNS, headers, screenshots", color: "cyan" },
  { id: "email", label: "Email Forensics Report", icon: "✉️", desc: "Header analysis, SPF/DKIM/DMARC, URLs, attachments", color: "blue" },
  { id: "malware", label: "Malware Analysis Report", icon: "🦠", desc: "PE analysis, YARA, strings, MITRE ATT&CK", color: "red" },
  { id: "network", label: "Network Forensics Report", icon: "🌐", desc: "PCAP analysis, sessions, IOC extraction", color: "violet" },
  { id: "memory", label: "Memory Analysis Report", icon: "🧠", desc: "Volatility output, processes, connections, DLLs", color: "emerald" },
  { id: "executive", label: "Executive Summary", icon: "📊", desc: "High-level non-technical incident summary", color: "amber" },
];

const STAGES = [
  "1. Evidence", "2. Correlation", "3. Timeline", "4. IOC",
  "5. MITRE", "6. Risk Score", "7. AI Summary", "8. PDF"
];

export default function Reports() {
  const [generating, setGenerating] = useState<string | null>(null);
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [caseName, setCaseName] = useState("CASE-2401 Cyber Incident");
  const [targetSubject, setTargetSubject] = useState("Corporate Network DMZ");

  const handleDownloadPDF = async () => {
    setDownloadingPdf(true);
    try {
      const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";
      const response = await fetch(`${API_BASE}/reports/pdf/download`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ case_name: caseName, target_subject: targetSubject })
      });

      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `Forensic_Report_${caseName.replace(/\s+/g, "_")}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } else {
        alert("Failed to generate PDF. Make sure backend API is running.");
      }
    } catch (e) {
      console.error(e);
      alert("Error contacting PDF Report service.");
    } finally {
      setDownloadingPdf(false);
    }
  };

  async function generate(id: string) {
    setGenerating(id);
    if (id === "master" || id === "executive") {
      await handleDownloadPDF();
    } else {
      await new Promise(r => setTimeout(r, 1500));
    }
    setGenerating(null);
  }

  return (
    <AppLayout title="Forensic Report Generation">
      <div className="max-w-6xl mx-auto space-y-8 p-4">
        {/* Header */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-slate-900/80 p-6 rounded-xl border border-slate-800">
          <div>
            <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
              <FileBarChart className="w-7 h-7 text-cyan-400" />
              Forensic Report & Investigation Pipeline
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Generate publication-ready PDF forensic investigation reports with automated evidence correlation and AI synthesis.
            </p>
          </div>
          <button
            onClick={handleDownloadPDF}
            disabled={downloadingPdf}
            className="flex items-center gap-2 px-5 py-3 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold rounded-lg shadow-lg shadow-cyan-900/30 transition text-sm disabled:opacity-50"
          >
            {downloadingPdf ? <RefreshCw className="w-4 h-4 animate-spin" /> : <FileDown className="w-4 h-4" />}
            Download Master PDF Report
          </button>
        </div>

        {/* 8-Stage Pipeline Diagram Visualizer */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
          <h2 className="text-lg font-semibold text-slate-200 flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-amber-400" />
            Automated 8-Stage Investigation Pipeline Flow
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2">
            {STAGES.map((stageName, i) => (
              <div key={i} className="bg-slate-950 border border-cyan-500/30 rounded-lg p-3 text-center flex flex-col items-center justify-between space-y-2">
                <span className="text-xs font-bold text-cyan-400">{stageName}</span>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              </div>
            ))}
          </div>
        </div>

        {/* Case & Target Input Config */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Investigation Case Title</label>
            <input
              type="text"
              value={caseName}
              onChange={(e) => setCaseName(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 text-sm focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Target Subject / Asset</label>
            <input
              type="text"
              value={targetSubject}
              onChange={(e) => setTargetSubject(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 text-sm focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        {/* Report Templates */}
        <div>
          <h3 className="text-xs font-semibold text-slate-400 mb-3 uppercase tracking-widest">Available Report Templates</h3>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {REPORT_TEMPLATES.map(({ id, label, icon, desc }) => (
              <div key={id} className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 hover:border-cyan-500/40 transition flex flex-col justify-between space-y-4">
                <div>
                  <div className="flex items-center gap-3 mb-2">
                    <div className="text-2xl">{icon}</div>
                    <div className="text-sm font-semibold text-slate-200">{label}</div>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{desc}</p>
                </div>
                <button
                  onClick={() => generate(id)}
                  disabled={generating === id}
                  className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg border border-slate-700 transition flex items-center justify-center gap-2"
                >
                  {generating === id ? (
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Download className="w-3.5 h-3.5 text-cyan-400" />
                  )}
                  {generating === id ? "Generating PDF..." : "Generate PDF Report"}
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
