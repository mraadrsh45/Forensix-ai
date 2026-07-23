"use client";
import { useState } from "react";
import Link from "next/link";
import { Shield, Eye, EyeOff, Loader2, Lock, ArrowRight } from "lucide-react";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [mfa, setMfa] = useState(false);
  const [totp, setTotp] = useState("");
  const [error, setError] = useState("");

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (!email || !password) { setError("Please enter email and password"); return; }
    setLoading(true);
    await new Promise(r => setTimeout(r, 1200));
    setLoading(false);
    setMfa(true);
  }

  async function handleMFA(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    await new Promise(r => setTimeout(r, 1000));
    window.location.href = "/dashboard";
  }

  return (
    <div className="min-h-screen bg-[#060c17] flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background effects */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_30%_50%,rgba(6,182,212,0.07)_0%,transparent_60%)]" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_70%_30%,rgba(139,92,246,0.06)_0%,transparent_60%)]" />
      <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9InJnYmEoMTQ4LDE2MywxODQsMC4wMikiIGZpbGwtb3BhY2l0eT0iMSI+PHBhdGggZD0iTTM2IDM0djZoNnYtNmgtNnptNiA2djZoNnYtNmgtNnptLTEyIDB2NmgtNnY2aDZ2LTZoNnYtNmgtNnoiLz48L2c+PC9nPjwvc3ZnPg==')] opacity-30" />

      <div className="w-full max-w-md relative z-10">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 mb-4 shadow-lg shadow-cyan-500/20">
            <Shield className="w-7 h-7 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">ForensiX<span className="text-cyan-400"> AI</span></h1>
          <p className="text-sm text-slate-500 mt-1">Enterprise Digital Forensics Platform</p>
        </div>

        <div className="glass-strong rounded-2xl p-8 border border-white/[0.08] shadow-2xl">
          {!mfa ? (
            <>
              <h2 className="text-lg font-semibold text-slate-200 mb-1">Sign In</h2>
              <p className="text-xs text-slate-500 mb-6">Access your investigation workspace</p>

              {error && (
                <div className="mb-4 px-3 py-2.5 rounded-lg bg-red-500/10 border border-red-500/20 text-xs text-red-400">{error}</div>
              )}

              <form onSubmit={handleLogin} className="space-y-4">
                <div>
                  <label className="text-xs text-slate-400 mb-1.5 block">Email Address</label>
                  <input value={email} onChange={e => setEmail(e.target.value)}
                    type="email" placeholder="analyst@forensix.ai" className="forensic-input" />
                </div>
                <div>
                  <label className="text-xs text-slate-400 mb-1.5 block">Password</label>
                  <div className="relative">
                    <input value={password} onChange={e => setPassword(e.target.value)}
                      type={showPw ? "text" : "password"} placeholder="••••••••••" className="forensic-input pr-10" />
                    <button type="button" onClick={() => setShowPw(!showPw)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
                      {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
                <button type="submit" disabled={loading} className="btn-primary w-full justify-center py-2.5">
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Lock className="w-4 h-4" />}
                  {loading ? "Authenticating..." : "Continue"}
                </button>
              </form>
            </>
          ) : (
            <>
              <div className="text-center mb-6">
                <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mx-auto mb-3">
                  <Lock className="w-6 h-6 text-cyan-400" />
                </div>
                <h2 className="text-lg font-semibold text-slate-200">Two-Factor Auth</h2>
                <p className="text-xs text-slate-500 mt-1">Enter the 6-digit code from your authenticator app</p>
              </div>
              <form onSubmit={handleMFA} className="space-y-4">
                <input value={totp} onChange={e => setTotp(e.target.value)}
                  placeholder="000000" maxLength={6}
                  className="forensic-input text-center text-2xl font-mono tracking-[0.5em] py-3" />
                <button type="submit" disabled={loading} className="btn-primary w-full justify-center py-2.5">
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ArrowRight className="w-4 h-4" />}
                  {loading ? "Verifying..." : "Verify & Access"}
                </button>
                <button type="button" onClick={() => setMfa(false)} className="btn-ghost w-full justify-center py-2 text-sm">
                  ← Back
                </button>
              </form>
            </>
          )}

          <div className="mt-6 pt-4 border-t border-white/[0.06] flex items-center justify-center gap-2 text-xs text-slate-600">
            <Lock className="w-3 h-3" />
            TLS 1.3 · AES-256 · SOC 2 Compliant
          </div>
        </div>

        <div className="mt-4 text-center">
          <Link href="/dashboard" className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center justify-center gap-1">
            Skip to Dashboard (Demo) <ArrowRight className="w-3 h-3" />
          </Link>
        </div>
      </div>
    </div>
  );
}
