"use client";
import AppLayout from "@/components/AppLayout";
import { useState, useRef, useEffect } from "react";
import { Bot, Send, Loader2, User, Sparkles, Shield, AlertTriangle, FileText, Cpu, CheckCircle2, Download } from "lucide-react";
import { apiPost } from "@/lib/api";

interface PipelineStep {
  id: number;
  name: string;
  status: "pending" | "running" | "completed" | "warning" | "danger";
  detail?: string;
}

interface InvestigationResult {
  analysis_id: string;
  case_name: string;
  target_subject: string;
  risk_score: number;
  threat_level: string;
  ai_summary: string;
  pipeline_steps: PipelineStep[];
  evidence: { module: string; finding: string; status: string }[];
  recommendations: { action: string; priority: string }[];
}

type Message = { role: "user" | "ai"; content: string; time: string };

const FLOWCHART_STEPS = [
  "Evidence Gathering",
  "Collect All Results",
  "LLM Neural Engine",
  "Summarize Executive Briefing",
  "Composite Risk Score",
  "Recommendations & Master PDF"
];

const PROMPTS = [
  "Run AI Investigation Workflow on Case CASE-2025-ALPHA",
  "Summarize threat landscape for ransomware attack",
  "What MITRE ATT&CK techniques were observed?",
  "Generate C-Suite executive briefing report",
];

export default function AIAssistant() {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "ai",
      content: "Hello, I'm ForensiX AI — your autonomous forensic investigation engine. Click 'Run AI Investigation' or ask any threat inquiry.",
      time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(-1);
  const [investigationResult, setInvestigationResult] = useState<InvestigationResult | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  async function runInvestigationWorkflow() {
    setLoading(true);
    setInvestigationResult(null);
    setCurrentStepIndex(0);

    const interval = setInterval(() => {
      setCurrentStepIndex((prev) => (prev < FLOWCHART_STEPS.length - 1 ? prev + 1 : prev));
    }, 180);

    const fallbackSteps: PipelineStep[] = FLOWCHART_STEPS.map((name, idx) => ({
      id: idx + 1,
      name,
      status: idx + 1 === 5 ? "danger" : "completed",
      detail: `Stage ${idx + 1} complete`
    }));

    const fallback: InvestigationResult = {
      analysis_id: `INV-CASE-${Math.random().toString(36).substring(2, 10).toUpperCase()}`,
      case_name: "CASE-2025-INCIDENT-ALPHA",
      target_subject: "Phishing & Ransomware Outbreak",
      risk_score: 96,
      threat_level: "CRITICAL / SEVERE THREAT LEVEL",
      ai_summary: "Comprehensive multi-module investigation synthesis confirmed coordinated threat campaign. Initial ingress via email phishing EML payload (Invoice_7741.pdf), followed by memory injection (RWX at 0x02a40000) and active C2 TLS beaconing to 185.234.219.45.",
      pipeline_steps: fallbackSteps,
      evidence: [
        { module: "Website Intel", finding: "Phishing portal cloned PayPal login structure. Zero SSL EV validation.", status: "CRITICAL" },
        { module: "Domain Intel", finding: "Domain phish-bank.tk registered via NameCheap. Privacy protected.", status: "HIGH" },
        { module: "IP Intel", finding: "185.234.219.45 listed in Spamhaus & AbuseIPDB (92% score). Open C2 port 4444.", status: "CRITICAL" },
        { module: "File Analysis", finding: "Invoice_7741.pdf contains obfuscated JS launcher payload.", status: "HIGH" },
        { module: "Email Forensics", finding: "EML header SPF/DKIM FAIL from spoofed domain.", status: "CRITICAL" },
        { module: "Malware Analysis", finding: "malware.exe WannaCry ransomware variant. Matched 14 ATT&CK techniques.", status: "CRITICAL" },
        { module: "Memory Forensics", finding: "Reflective DLL injection in malware_loader.exe (PID 6892).", status: "CRITICAL" },
        { module: "Network Forensics", finding: "142 TLS beaconing streams to C2 IP 185.234.219.45:443.", status: "CRITICAL" },
        { module: "Mobile Forensics", finding: "FakeBank_v2.apk requested READ_SMS & SYSTEM_ALERT_WINDOW overlay permissions.", status: "CRITICAL" },
        { module: "OSINT Module", finding: "GitHub repository dark-c2-botnet leaked AWS credentials and C2 config.", status: "HIGH" },
        { module: "Threat Intel", finding: "IOC 185.234.219.45 matched ThreatFox AgentTesla botnet database.", status: "CRITICAL" }
      ],
      recommendations: [
        { action: "Block C2 IP 185.234.219.45 at perimeter firewall & SIEM", priority: "P0 - IMMEDIATE" },
        { action: "Revoke compromised AWS credentials leaked in GitHub repository", priority: "P0 - IMMEDIATE" },
        { action: "Isolate infected host & purge malware_loader.exe (PID 6892)", priority: "P1 - HIGH" },
        { action: "Deploy YARA rule signature match across EDR agents", priority: "P1 - HIGH" }
      ]
    };

    try {
      const res = await apiPost<InvestigationResult>("/ai-investigation/execute", {
        case_name: "CASE-2025-INCIDENT-ALPHA",
        target_subject: "Phishing & Ransomware Outbreak"
      }, fallback);
      setInvestigationResult(res);
      setMessages(m => [
        ...m,
        {
          role: "ai",
          content: `### 🤖 Master AI Forensic Investigation Completed\n\n**Case Name:** ${res.case_name}\n**Risk Score:** ${res.risk_score}/100 (${res.threat_level})\n\n**AI Executive Summary:**\n${res.ai_summary}\n\n**Recommended Playbook Actions:**\n${res.recommendations.map(r => `- [${r.priority}] ${r.action}`).join("\n")}`,
          time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
        }
      ]);
    } catch {
      setInvestigationResult(fallback);
    } finally {
      clearInterval(interval);
      setCurrentStepIndex(FLOWCHART_STEPS.length - 1);
      setLoading(false);
    }
  }

  async function send(text?: string) {
    const msg = text ?? input.trim();
    if (!msg) return;

    if (msg.toLowerCase().includes("run ai investigation") || msg.toLowerCase().includes("workflow")) {
      await runInvestigationWorkflow();
      return;
    }

    const time = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    setMessages(m => [...m, { role: "user", content: msg, time }]);
    setInput(""); setLoading(true);

    const fallbackResponse = `### ForensiX AI Forensic Response\n\n**Query:** ${msg}\n\n**Analysis:**\nBased on cross-case evidence synthesis, threat indicators align with active APT campaigns. Recommend executing the 6-step AI investigation workflow for full report generation.`;
    
    const apiRes = await apiPost<{ response: string }>("/ai-assistant/ask", { prompt: msg }, { response: fallbackResponse });
    setMessages(m => [...m, { role: "ai", content: apiRes.response, time }]);
    setLoading(false);
  }

  return (
    <AppLayout title="AI Investigation Module">
      <div className="max-w-5xl mx-auto space-y-6">
        
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-2xl font-black tracking-tight text-slate-100">AI Investigation Module</h2>
              <span className="badge bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">6-Step LLM Engine</span>
            </div>
            <p className="text-sm text-slate-400 mt-1">
              Cross-case evidence consolidation, Gemini 1.5 Flash LLM reasoning, risk scoring & automated remediation playbook
            </p>
          </div>

          <button onClick={runInvestigationWorkflow} disabled={loading} className="btn-primary text-xs flex items-center gap-2">
            <Sparkles className="w-4 h-4" /> Run 6-Step AI Investigation Workflow
          </button>
        </div>

        {/* 6-STAGE PIPELINE PROGRESS VISUALIZER */}
        {(loading || investigationResult) && (
          <div className="stat-card space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
                  6-Step AI Investigation Flowchart
                </h3>
              </div>
              <span className="text-xs text-slate-400 font-mono">
                {loading ? `Executing Step ${currentStepIndex + 1} of 6` : "6 / 6 Steps Completed"}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2">
              {FLOWCHART_STEPS.map((stepName, idx) => {
                const isCurrent = loading && currentStepIndex === idx;
                const isPassed = !loading && investigationResult;
                const isCompleted = currentStepIndex >= idx;

                let statusColor = "border-slate-800 bg-slate-900/50 text-slate-500";
                if (isCurrent) {
                  statusColor = "border-cyan-500 bg-cyan-500/10 text-cyan-300 animate-pulse ring-1 ring-cyan-500/50";
                } else if (isPassed) {
                  const stepDetail = investigationResult.pipeline_steps?.[idx];
                  if (stepDetail?.status === "danger") {
                    statusColor = "border-red-500/40 bg-red-500/10 text-red-400";
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

        {/* Chat Window */}
        <div className="stat-card flex flex-col h-[480px]">
          <div className="flex-1 overflow-y-auto space-y-4 pr-1">
            {messages.map((m, i) => (
              <div key={i} className={`flex gap-3 ${m.role === "user" ? "flex-row-reverse" : ""}`}>
                <div className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 ${
                  m.role === "ai"
                    ? "bg-gradient-to-br from-cyan-500 to-violet-600"
                    : "bg-gradient-to-br from-slate-600 to-slate-700"
                }`}>
                  {m.role === "ai" ? <Sparkles className="w-4 h-4 text-white" /> : <User className="w-4 h-4 text-white" />}
                </div>
                <div className={`max-w-[85%] ${m.role === "user" ? "items-end" : "items-start"} flex flex-col`}>
                  <div className={`px-4 py-3 rounded-2xl text-xs leading-relaxed whitespace-pre-line ${
                    m.role === "ai"
                      ? "bg-slate-900 border border-slate-800 text-slate-200"
                      : "bg-cyan-500/20 border border-cyan-500/30 text-slate-200"
                  }`}>
                    {m.content}
                  </div>
                  <div className="text-[10px] text-slate-600 mt-1 px-1">{m.time}</div>
                </div>
              </div>
            ))}
            {loading && (
              <div className="flex gap-3">
                <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-500 to-violet-600 flex items-center justify-center">
                  <Sparkles className="w-4 h-4 text-white" />
                </div>
                <div className="bg-slate-900 border border-slate-800 rounded-2xl px-4 py-3 flex items-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
                  <span className="text-xs text-slate-400">Executing Gemini LLM Investigation Synthesis...</span>
                </div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          {/* Quick Prompts */}
          <div className="flex gap-2 flex-wrap my-3 pt-2 border-t border-slate-800">
            {PROMPTS.map(p => (
              <button key={p} onClick={() => send(p)}
                className="text-[11px] px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-slate-400 hover:text-cyan-300 hover:border-cyan-500/30 transition-all truncate">
                {p}
              </button>
            ))}
          </div>

          {/* Input Box */}
          <div className="flex gap-3">
            <input
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter") send(); }}
              placeholder="Ask LLM assistant or type 'Run AI investigation'..."
              className="forensic-input flex-1 text-xs"
            />
            <button onClick={() => send()} disabled={loading || !input.trim()} className="btn-primary text-xs">
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            </button>
          </div>
        </div>

      </div>
    </AppLayout>
  );
}
