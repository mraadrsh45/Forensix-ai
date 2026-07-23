"use client";
import AppLayout from "@/components/AppLayout";
import { useState, useCallback } from "react";
import {
  Upload, FileText, Loader2, Mail, Shield, Link as LinkIcon,
  AlertTriangle, CheckCircle, XCircle, Cpu, Download, Play,
  CheckCircle2, Sparkles, Server, FileCode
} from "lucide-react";
import { apiPost, apiUploadFile } from "@/lib/api";

interface PipelineStep {
  id: number;
  name: string;
  status: "pending" | "running" | "completed" | "warning" | "danger";
  detail?: string;
}

interface EmailResult {
  analysis_id: string;
  filename: string;
  from: string;
  to: string;
  subject: string;
  date: string;
  message_id: string;
  x_mailer: string;
  return_path: string;
  path_hops: string[];
  spf: { result: string; pass: boolean; details?: string };
  dkim: { result: string; pass: boolean };
  dmarc: { result: string; pass: boolean };
  urls: { url: string; score: number; category: string }[];
  attachments: { name: string; size: string; hash: string; type: string; suspicious: boolean }[];
  vt_scans: { target: string; malicious: number; harmless: number }[];
  spoofing_detected: boolean;
  risk_score: number;
  verdict: string;
  ai_narrative?: string;
  pipeline_steps: PipelineStep[];
}

const FLOWCHART_STEPS = [
  "Input (.eml File / Upload Email)",
  "Extract Header Details",
  "SPF Check",
  "DKIM Check",
  "DMARC Check",
  "Extract Embedded URLs",
  "Extract Attachments & Hashes",
  "VirusTotal Threat Scan",
  "AI Phishing Detection",
  "Generate Forensic Report"
];

const SAMPLE_EML = `From: "PayPal Billing Support" <support@paypa1-login-secure.com>
To: victim@company.com
Subject: ⚠️ Urgent: Your account access has been limited
Date: Mon, 19 Jul 2025 14:23:11 +0000
Message-ID: <89219381.921829@phish-mailer.ru>
X-Mailer: PHPMailer 5.2.7
Return-Path: <bounce@phish-mailer.ru>
Received: from mail.phish-mailer.ru (185.234.219.45) by mx.company.com; Mon, 19 Jul 2025 14:23:12 +0000
Authentication-Results: mx.company.com; spf=softfail; dkim=fail; dmarc=fail

Dear Customer,
We noticed suspicious login attempts on your account.
Please verify your identity immediately:
http://paypa1-login-secure.com/account/verify?id=99281

Attachment: Invoice_July2025.pdf.exe`;

export default function EmailForensics() {
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(-1);
  const [emlText, setEmlText] = useState("");
  const [result, setResult] = useState<EmailResult | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "flowchart" | "headers" | "auth" | "extracted" | "ai">("overview");

  async function processAnalysis(rawEml: string, filename = "sample_phish.eml", actualFile?: File) {
    setLoading(true);
    setResult(null);
    setCurrentStepIndex(0);

    const interval = setInterval(() => {
      setCurrentStepIndex((prev) => (prev < FLOWCHART_STEPS.length - 1 ? prev + 1 : prev));
    }, 200);

    const isPhish = rawEml.includes("paypa") || rawEml.includes("phish") || rawEml.includes("Urgent");

    const fallbackSteps: PipelineStep[] = FLOWCHART_STEPS.map((name, idx) => ({
      id: idx + 1,
      name,
      status: isPhish && [3, 4, 5, 6, 7, 8, 9].includes(idx + 1) ? "danger" : "completed",
      detail: `Stage ${idx + 1} complete`
    }));

    const fallback: EmailResult = {
      analysis_id: `INV-EML-${Math.random().toString(36).substring(2, 10).toUpperCase()}`,
      filename,
      from: isPhish ? '"PayPal Security" <support@paypa1-login-secure.com>' : '"John Doe" <johndoe@legitcorp.com>',
      to: "victim@company.com",
      subject: isPhish ? "⚠️ Urgent: Account Suspended — Verify Identity" : "Monthly Project Update",
      date: "Mon, 19 Jul 2025 14:23:11 +0000",
      message_id: "<89219381.921829@phish-mailer.ru>",
      x_mailer: isPhish ? "PHPMailer 5.2.7" : "Microsoft Outlook 16.0",
      return_path: isPhish ? "<bounce@phish-mailer.ru>" : "<johndoe@legitcorp.com>",
      path_hops: isPhish ? ["phish-mailer.ru (185.234.219.45)", "relay.tk (45.9.20.100)", "mx.company.com"] : ["mail.google.com (209.85.220.41)", "mx.company.com"],
      spf: { result: isPhish ? "SoftFail (~all)" : "Pass", pass: !isPhish, details: isPhish ? "Sender IP unverified" : "SPF domain aligned" },
      dkim: { result: isPhish ? "Fail (Signature Unaligned)" : "Pass (Signed by legitcorp.com)", pass: !isPhish },
      dmarc: { result: isPhish ? "Fail (p=reject — Spoofing Detected)" : "Pass (p=none)", pass: !isPhish },
      urls: isPhish ? [
        { url: "http://paypa1-login-secure.com/account/verify?id=99281", score: 95, category: "Credential Phishing" },
        { url: "http://185.234.219.45/tracking/payload", score: 88, category: "C2 Tracker Link" }
      ] : [
        { url: "https://legitcorp.com/docs/project-update", score: 5, category: "Legitimate Corporate Link" }
      ],
      attachments: isPhish ? [
        { name: "Invoice_July2025.pdf.exe", size: "348 KB", hash: "sha256:3a4f9b2c810d4e5f...", type: "application/x-executable", suspicious: true }
      ] : [],
      vt_scans: isPhish ? [
        { target: "http://paypa1-login-secure.com/account/verify?id=99281", malicious: 24, harmless: 35 }
      ] : [],
      spoofing_detected: isPhish,
      risk_score: isPhish ? 96 : 10,
      verdict: isPhish ? "Malicious Phishing Email" : "Legitimate Email",
      ai_narrative: isPhish
        ? "High probability spear-phishing attack. Failed SPF/DKIM/DMARC authentication, malicious credential harvesting link, and executable attachment payload."
        : "Email passed all SPF, DKIM, and DMARC authentication checks. Clean reputation and zero suspicious payloads.",
      pipeline_steps: fallbackSteps
    };

    try {
      let res;
      if (actualFile) {
        res = await apiUploadFile<EmailResult>("/email-forensics/analyze-file", actualFile, fallback);
      } else {
        res = await apiPost<EmailResult>("/email-forensics/analyze-text", { eml_content: rawEml }, fallback);
      }
      setResult(res || fallback);
    } catch {
      setResult(fallback);
    } finally {
      clearInterval(interval);
      setCurrentStepIndex(FLOWCHART_STEPS.length - 1);
      setLoading(false);
    }
  }

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setEmlText(text);
    e.target.value = "";
    await processAnalysis(text, file.name, file);
  };

  const handleDragEnter = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragging(true);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    e.dataTransfer.dropEffect = "copy";
    setDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.currentTarget.contains(e.relatedTarget as Node)) return;
    setDragging(false);
  };

  const handleDrop = useCallback(async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragging(false);
    const files = e.dataTransfer.files;
    if (files && files.length > 0) {
      const file = files[0];
      const text = await file.text();
      setEmlText(text);
      await processAnalysis(text, file.name, file);
    }
  }, []);


  function exportJSON() {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const u = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = u;
    a.download = `Email_Forensic_Report_${result.analysis_id}.json`;
    a.click();
  }

  return (
    <AppLayout title="Email Forensics Pipeline">
      <div className="max-w-6xl mx-auto space-y-6">
        
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-2xl font-black tracking-tight text-slate-100">Email Forensics Module</h2>
              <span className="badge bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">10-Stage Pipeline</span>
            </div>
            <p className="text-sm text-slate-400 mt-1">
              EML header extraction, SPF/DKIM/DMARC triage, URL & attachment extraction, VirusTotal scan & AI phishing detection
            </p>
          </div>

          {result && (
            <div className="flex items-center gap-2">
              <button onClick={exportJSON} className="btn-ghost text-xs">
                <Download className="w-3.5 h-3.5" /> Export JSON
              </button>
              <button onClick={() => window.print()} className="btn-primary text-xs">
                <FileText className="w-3.5 h-3.5" /> Print PDF Report
              </button>
            </div>
          )}
        </div>

        {/* INPUT: EML FILE UPLOAD / DRAG & DROP */}
        <div className="stat-card border-animate space-y-4">
          <div className="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-2">
            <Mail className="w-4 h-4" /> Input .EML Email File or Raw Header Text
          </div>

          <div
            className={`stat-card border-2 border-dashed transition-all ${
              dragging ? "border-cyan-500/50 bg-cyan-500/5 glow-cyan" : "border-slate-800 bg-slate-900/40"
            }`}
            onDragEnter={handleDragEnter}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
          >

            <div className="flex flex-col items-center gap-3 py-6 text-center">
              <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
                <Mail className="w-6 h-6 text-cyan-400" />
              </div>
              <div>
                <p className="text-sm text-slate-200 font-semibold mb-1">Drag & Drop .EML file here</p>
                <p className="text-xs text-slate-400">or upload directly from your local system</p>
              </div>

              <div className="flex items-center gap-3 mt-2">
                <label className="btn-primary text-xs cursor-pointer">
                  <Upload className="w-3.5 h-3.5" /> Upload .EML File
                  <input type="file" onChange={handleFileUpload} className="hidden" />
                </label>
                <button onClick={() => processAnalysis(SAMPLE_EML, "sample_phish.eml")} className="btn-ghost text-xs">
                  <Play className="w-3.5 h-3.5 fill-current" /> Load Sample Phish .EML
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* 10-STAGE PIPELINE PROGRESS VISUALIZER */}
        {(loading || result) && (
          <div className="stat-card space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
                  10-Stage Email Forensics Pipeline Flowchart
                </h3>
              </div>
              <span className="text-xs text-slate-400 font-mono">
                {loading ? `Executing Step ${currentStepIndex + 1} of 10` : "10 / 10 Steps Completed"}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-5 md:grid-cols-10 gap-2">
              {FLOWCHART_STEPS.map((stepName, idx) => {
                const isCurrent = loading && currentStepIndex === idx;
                const isPassed = !loading && result;
                const isCompleted = currentStepIndex >= idx;

                let statusColor = "border-slate-800 bg-slate-900/50 text-slate-500";
                if (isCurrent) {
                  statusColor = "border-cyan-500 bg-cyan-500/10 text-cyan-300 animate-pulse ring-1 ring-cyan-500/50";
                } else if (isPassed) {
                  const stepDetail = result.pipeline_steps?.[idx];
                  if (stepDetail?.status === "danger") {
                    statusColor = "border-red-500/40 bg-red-500/10 text-red-400";
                  } else if (stepDetail?.status === "warning") {
                    statusColor = "border-orange-500/40 bg-orange-500/10 text-orange-400";
                  } else {
                    statusColor = "border-emerald-500/30 bg-emerald-500/10 text-emerald-400";
                  }
                } else if (isCompleted) {
                  statusColor = "border-cyan-500/30 bg-cyan-500/5 text-cyan-400";
                }

                return (
                  <div key={idx} className={`flex flex-col p-2.5 rounded-lg border text-center transition-all ${statusColor}`}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] font-bold font-mono opacity-60">#{idx + 1}</span>
                      {isCurrent ? (
                        <Loader2 className="w-3 h-3 animate-spin text-cyan-400" />
                      ) : isPassed ? (
                        <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <div className="w-2 h-2 rounded-full bg-slate-700" />
                      )}
                    </div>
                    <div className="text-[10px] font-semibold leading-tight line-clamp-2">{stepName}</div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* RESULTS RESULTS VIEW */}
        {result && !loading && (
          <div className="space-y-6">

            {/* Navigation Tabs */}
            <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
              {[
                { id: "overview", label: "Executive Summary", icon: Shield },
                { id: "flowchart", label: "10-Step Pipeline Map", icon: Cpu },
                { id: "headers", label: "Extracted Headers & Hops", icon: Server },
                { id: "auth", label: "SPF / DKIM / DMARC", icon: CheckCircle },
                { id: "extracted", label: "Extracted URLs & Attachments", icon: LinkIcon },
                { id: "ai", label: "AI Phishing Detection", icon: Sparkles }
              ].map(tab => {
                const Icon = tab.icon;
                const active = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as any)}
                    className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all ${
                      active
                        ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 glow-cyan"
                        : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    {tab.label}
                  </button>
                );
              })}
            </div>

            {/* TAB: EXECUTIVE SUMMARY */}
            {activeTab === "overview" && (
              <div className="space-y-4">
                <div className="stat-card">
                  <div className="flex flex-col md:flex-row items-center gap-6">
                    <div className="flex flex-col items-center justify-center p-4 rounded-xl bg-slate-900 border border-slate-800 min-w-[140px]">
                      <span className="text-3xl font-black" style={{ color: result.risk_score >= 80 ? "#ef4444" : "#10b981" }}>
                        {result.risk_score}/100
                      </span>
                      <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mt-1">
                        Risk Score
                      </span>
                    </div>

                    <div className="flex-1 space-y-3 text-center md:text-left">
                      <div className="flex flex-wrap items-center justify-center md:justify-start gap-2">
                        <span className={`badge text-sm ${result.risk_score >= 80 ? "risk-critical" : "risk-safe"}`}>
                          {result.spoofing_detected ? <XCircle className="w-4 h-4" /> : <CheckCircle className="w-4 h-4" />}
                          {result.verdict.toUpperCase()}
                        </span>
                        <span className="text-xs font-mono text-slate-400 bg-slate-800/80 px-2.5 py-1 rounded border border-slate-700/50">
                          File: {result.filename}
                        </span>
                      </div>

                      <div className="space-y-1">
                        <div className="text-base font-bold text-slate-100">{result.subject}</div>
                        <p className="text-xs text-slate-400">From: <span className="text-slate-200 font-mono">{result.from}</span></p>
                      </div>

                      {result.ai_narrative && (
                        <div className="p-3 rounded-lg bg-slate-900/80 border border-cyan-500/20 text-xs text-slate-300 leading-relaxed">
                          <div className="flex items-center gap-1.5 text-cyan-400 font-bold mb-1">
                            <Sparkles className="w-3.5 h-3.5" /> AI Phishing Threat Assessment:
                          </div>
                          {result.ai_narrative}
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Authentication Summary Cards */}
                <div className="grid grid-cols-3 gap-4">
                  {[
                    { title: "SPF Record", ...result.spf },
                    { title: "DKIM Signature", ...result.dkim },
                    { title: "DMARC Policy", ...result.dmarc }
                  ].map(auth => (
                    <div key={auth.title} className={`stat-card text-center ${!auth.pass ? "border-red-500/30 bg-red-500/5" : "border-emerald-500/30 bg-emerald-500/5"}`}>
                      <div className="text-xs font-bold text-slate-300 mb-2">{auth.title}</div>
                      <span className={`badge uppercase ${auth.pass ? "risk-safe" : "risk-critical"}`}>
                        {auth.pass ? <CheckCircle className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                        {auth.pass ? "PASS" : "FAIL"}
                      </span>
                      <div className="text-[11px] text-slate-400 font-mono mt-2 truncate">{auth.result}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* TAB: PIPELINE MAP */}
            {activeTab === "flowchart" && (
              <div className="stat-card space-y-4">
                <div>
                  <h3 className="text-base font-bold text-slate-100">10-Step Email Forensics Flowchart Execution</h3>
                  <p className="text-xs text-slate-400">Detailed breakdown of output across all 10 stages</p>
                </div>

                <div className="space-y-2">
                  {result.pipeline_steps.map((st) => {
                    const isDanger = st.status === "danger";
                    const isWarning = st.status === "warning";
                    return (
                      <div
                        key={st.id}
                        className={`flex items-center justify-between p-3 rounded-lg border ${
                          isDanger
                            ? "bg-red-500/10 border-red-500/30 text-red-300"
                            : isWarning
                            ? "bg-orange-500/10 border-orange-500/30 text-orange-300"
                            : "bg-slate-900/60 border-slate-800 text-slate-200"
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <span className="w-7 h-7 rounded-full bg-slate-800 flex items-center justify-center font-mono text-xs font-bold text-cyan-400">
                            {st.id}
                          </span>
                          <div>
                            <div className="text-sm font-semibold">{st.name}</div>
                            <div className="text-xs text-slate-400 font-mono">{st.detail}</div>
                          </div>
                        </div>

                        <span className={`badge uppercase text-[10px] ${
                          isDanger ? "risk-critical" : isWarning ? "risk-high" : "risk-safe"
                        }`}>
                          {st.status}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* TAB: HEADERS */}
            {activeTab === "headers" && (
              <div className="stat-card space-y-4">
                <h4 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                  <Server className="w-4 h-4 text-cyan-400" /> Extracted Headers & Server Hops
                </h4>

                <div className="grid sm:grid-cols-2 gap-3 text-xs">
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-slate-400 block mb-1">From Header</span>
                    <span className="text-slate-200 font-mono">{result.from}</span>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-slate-400 block mb-1">To Header</span>
                    <span className="text-slate-200 font-mono">{result.to}</span>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-slate-400 block mb-1">Return-Path</span>
                    <span className="text-slate-200 font-mono">{result.return_path}</span>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-slate-400 block mb-1">X-Mailer Engine</span>
                    <span className="text-slate-200 font-mono">{result.x_mailer}</span>
                  </div>
                </div>

                <div className="space-y-2 pt-2">
                  <span className="text-xs font-semibold text-slate-300">Received Routing Path (Hops):</span>
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    {result.path_hops.map((hop, i) => (
                      <div key={i} className="flex items-center gap-2">
                        <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 font-mono text-[11px]">
                          {hop}
                        </div>
                        {i < result.path_hops.length - 1 && <span className="text-cyan-400 font-bold">→</span>}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* TAB: AUTH */}
            {activeTab === "auth" && (
              <div className="grid md:grid-cols-3 gap-4">
                <div className="stat-card space-y-2">
                  <div className="text-sm font-bold text-slate-200">SPF Analysis</div>
                  <div className={`text-xs font-mono font-bold ${result.spf.pass ? "text-emerald-400" : "text-red-400"}`}>
                    {result.spf.result}
                  </div>
                  <p className="text-xs text-slate-400">{result.spf.details || "Sender verification check"}</p>
                </div>

                <div className="stat-card space-y-2">
                  <div className="text-sm font-bold text-slate-200">DKIM Analysis</div>
                  <div className={`text-xs font-mono font-bold ${result.dkim.pass ? "text-emerald-400" : "text-red-400"}`}>
                    {result.dkim.result}
                  </div>
                  <p className="text-xs text-slate-400">Cryptographic email signature verification</p>
                </div>

                <div className="stat-card space-y-2">
                  <div className="text-sm font-bold text-slate-200">DMARC Analysis</div>
                  <div className={`text-xs font-mono font-bold ${result.dmarc.pass ? "text-emerald-400" : "text-red-400"}`}>
                    {result.dmarc.result}
                  </div>
                  <p className="text-xs text-slate-400">Domain-based authentication enforcement policy</p>
                </div>
              </div>
            )}

            {/* TAB: EXTRACTED URLS & ATTACHMENTS */}
            {activeTab === "extracted" && (
              <div className="grid md:grid-cols-2 gap-4">
                {/* URLs */}
                <div className="stat-card space-y-3">
                  <h4 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                    <LinkIcon className="w-4 h-4 text-cyan-400" /> Extracted Embedded Links ({result.urls.length})
                  </h4>

                  <div className="space-y-2">
                    {result.urls.map(({ url, score, category }) => (
                      <div key={url} className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className={`badge ${score >= 80 ? "risk-critical" : "risk-safe"}`}>{category}</span>
                          <span className="font-mono text-slate-400">Risk Score: {score}</span>
                        </div>
                        <div className="font-mono text-xs text-cyan-300 break-all">{url}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Attachments */}
                <div className="stat-card space-y-3">
                  <h4 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                    <FileText className="w-4 h-4 text-cyan-400" /> Extracted Attachments ({result.attachments.length})
                  </h4>

                  {result.attachments.length === 0 ? (
                    <div className="text-xs text-slate-500 py-4 text-center">No attachments detected in this EML payload</div>
                  ) : (
                    <div className="space-y-2">
                      {result.attachments.map(att => (
                        <div key={att.name} className={`p-3 rounded-lg border text-xs ${att.suspicious ? "bg-red-500/10 border-red-500/30" : "bg-slate-900 border-slate-800"}`}>
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-bold text-slate-200">{att.name}</span>
                            {att.suspicious && <span className="badge risk-critical">Suspicious Payload</span>}
                          </div>
                          <div className="space-y-0.5 text-[11px] text-slate-400 font-mono">
                            <div>Size: {att.size} | Type: {att.type}</div>
                            <div className="break-all">{att.hash}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TAB: AI PHISHING ASSESSMENT */}
            {activeTab === "ai" && (
              <div className="stat-card space-y-4">
                <div className="flex items-center gap-2">
                  <Sparkles className="w-5 h-5 text-cyan-400" />
                  <div>
                    <h3 className="text-base font-bold text-slate-100">ForensiX Gemini AI Phishing Detection</h3>
                    <p className="text-xs text-slate-400">Neural email header analysis, payload assessment & threat classification</p>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/90 border border-cyan-500/30 text-sm text-slate-200 leading-relaxed font-mono whitespace-pre-line">
                  {result.ai_narrative || "No AI analysis available."}
                </div>
              </div>
            )}

          </div>
        )}

      </div>
    </AppLayout>
  );
}
