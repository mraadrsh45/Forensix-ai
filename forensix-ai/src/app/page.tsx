"use client";
import Link from "next/link";
import { Shield, Zap, Globe, Brain, FileText, Bug, Network, ArrowRight, CheckCircle, Lock, Eye, Activity } from "lucide-react";
import { useEffect, useRef } from "react";

const FEATURES = [
  { icon: Globe, title: "Website Intelligence", desc: "Real-time phishing detection, SSL analysis, DNS & WHOIS lookup with AI risk scoring." },
  { icon: Bug, title: "Malware Analysis", desc: "Static analysis, YARA scanning, VirusTotal integration, and MITRE ATT&CK mapping." },
  { icon: Brain, title: "Memory Forensics", desc: "Volatility 3 integration for process, DLL, registry, and network connection analysis." },
  { icon: Network, title: "Network Forensics", desc: "PCAP analysis, session reconstruction, IOC extraction, and suspicious traffic detection." },
  { icon: FileText, title: "Email Forensics", desc: "EML parsing, header analysis, SPF/DKIM/DMARC validation, and spoofing detection." },
  { icon: Zap, title: "AI Investigation", desc: "LLM-powered evidence summarization, risk assessment, and automated report generation." },
];

const STATS = [
  { label: "Threats Analyzed", value: "2.4M+", color: "text-cyan-400" },
  { label: "IOCs Tracked", value: "890K+", color: "text-violet-400" },
  { label: "Cases Resolved", value: "15K+", color: "text-emerald-400" },
  { label: "Accuracy Rate", value: "99.7%", color: "text-amber-400" },
];

export default function LandingPage() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;

    const chars = "01ABCDEF♦◆▲●";
    const cols = Math.floor(canvas.width / 20);
    const drops: number[] = Array(cols).fill(1);

    const draw = () => {
      ctx.fillStyle = "rgba(6, 12, 23, 0.05)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = "rgba(6, 182, 212, 0.15)";
      ctx.font = "13px monospace";
      drops.forEach((y, i) => {
        const char = chars[Math.floor(Math.random() * chars.length)];
        ctx.fillText(char, i * 20, y * 20);
        if (y * 20 > canvas.height && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      });
    };
    const interval = setInterval(draw, 80);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-[#060c17] text-white overflow-x-hidden">
      {/* Matrix rain background */}
      <canvas ref={canvasRef} className="fixed inset-0 w-full h-full opacity-30 pointer-events-none" />

      {/* Navbar */}
      <nav className="relative z-10 flex items-center justify-between px-6 py-4 border-b border-white/[0.06] bg-[#080e1a]/80 backdrop-blur sticky top-0">
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-8 h-8 rounded-lg overflow-hidden bg-black">
            <img src="/logo.png" alt="Logo" className="w-8 h-8 object-contain" />
          </div>
          <span className="text-white font-bold text-xl">ForensiX<span className="text-cyan-400"> AI</span></span>
        </div>
        <div className="hidden md:flex items-center gap-6 text-sm text-slate-400">
          {["Features", "Modules", "Pricing", "Docs"].map(l => (
            <a key={l} href="#" className="hover:text-white transition-colors">{l}</a>
          ))}
        </div>
        <div className="flex items-center gap-3">
          <Link href="/auth/login" className="btn-ghost py-2 px-4 text-sm">Sign In</Link>
          <Link href="/dashboard" className="btn-primary py-2 px-4 text-sm">
            Launch Platform <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative z-10 text-center px-6 pt-24 pb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-xs text-cyan-400 mb-8">
          <div className="pulse-dot w-1.5 h-1.5" />
          v2.0 Live — Real-time Threat Intelligence Active
        </div>
        <h1 className="text-5xl md:text-7xl font-black mb-6 leading-tight">
          <span className="gradient-text">ForensiX AI</span>
          <br />
          <span className="text-slate-200">Digital Forensics</span>
          <br />
          <span className="text-slate-400 text-4xl md:text-5xl font-bold">Redefined.</span>
        </h1>
        <p className="text-lg text-slate-400 max-w-2xl mx-auto mb-10 leading-relaxed">
          Enterprise-grade AI-powered forensics platform for SOC teams, incident responders,
          and digital investigators. Analyze threats across web, email, files, memory, and networks.
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <Link href="/dashboard" className="btn-primary text-base px-8 py-3">
            <Shield className="w-5 h-5" />
            Start Investigation
          </Link>
          <Link href="/website-intel" className="btn-ghost text-base px-8 py-3">
            <Eye className="w-5 h-5" />
            Live Demo
          </Link>
        </div>
      </section>

      {/* Stats */}
      <section className="relative z-10 px-6 py-10">
        <div className="max-w-4xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-4">
          {STATS.map(({ label, value, color }) => (
            <div key={label} className="stat-card text-center border-animate">
              <div className={`text-3xl font-black ${color} mb-1`}>{value}</div>
              <div className="text-xs text-slate-500 font-medium">{label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Features */}
      <section className="relative z-10 px-6 py-16">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-slate-100 mb-3">Complete Forensics Arsenal</h2>
            <p className="text-slate-400">12 specialized modules covering every aspect of digital investigation</p>
          </div>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-5">
            {FEATURES.map(({ icon: Icon, title, desc }) => (
              <div key={title} className="stat-card group hover:border-cyan-500/20 transition-all duration-300">
                <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mb-4 group-hover:bg-cyan-500/20 transition-colors">
                  <Icon className="w-5 h-5 text-cyan-400" />
                </div>
                <h3 className="text-base font-semibold text-slate-200 mb-2">{title}</h3>
                <p className="text-sm text-slate-500 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="relative z-10 px-6 py-20">
        <div className="max-w-3xl mx-auto text-center">
          <div className="glass-strong rounded-2xl p-12 border-animate">
            <Lock className="w-12 h-12 text-cyan-400 mx-auto mb-4" />
            <h2 className="text-3xl font-bold text-white mb-4">Ready to Investigate?</h2>
            <p className="text-slate-400 mb-8">Join 500+ security teams using ForensiX AI for enterprise-grade digital forensics.</p>
            <Link href="/dashboard" className="btn-primary text-base px-10 py-3">
              <Activity className="w-5 h-5" />
              Open Dashboard
            </Link>
            <div className="flex items-center justify-center gap-6 mt-8 text-xs text-slate-500">
              {["SOC 2 Compliant", "Chain of Custody", "AES-256 Encrypted", "99.9% Uptime"].map(f => (
                <div key={f} className="flex items-center gap-1.5">
                  <CheckCircle className="w-3 h-3 text-emerald-400" /> {f}
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <footer className="relative z-10 border-t border-white/[0.06] px-6 py-6 text-center text-xs text-slate-600">
        © 2025 ForensiX AI — Enterprise Digital Forensics Platform. All rights reserved.
      </footer>
    </div>
  );
}
