"use client";
import AppLayout from "@/components/AppLayout";
import { useState } from "react";
import { Key, Shield, Bell, Users, Database, Save, Check } from "lucide-react";

const API_KEYS = [
  { name: "VirusTotal", key: "VT-****-****-****", connected: true, icon: "🦠" },
  { name: "AbuseIPDB", key: "AI-****-****-****", connected: true, icon: "🛡️" },
  { name: "URLScan.io", key: "", connected: false, icon: "🔍" },
  { name: "Shodan", key: "", connected: false, icon: "📡" },
  { name: "SecurityTrails", key: "", connected: false, icon: "🔎" },
  { name: "AlienVault OTX", key: "OTX-****-****", connected: true, icon: "👽" },
  { name: "IPinfo", key: "IP-****-****", connected: true, icon: "📍" },
  { name: "Google Gemini", key: "GM-****-****", connected: true, icon: "🤖" },
];

export default function Settings() {
  const [saved, setSaved] = useState(false);

  async function save() {
    await new Promise(r => setTimeout(r, 800));
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  }

  return (
    <AppLayout title="Settings">
      <div className="max-w-3xl mx-auto space-y-6">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 mb-1">Platform Settings</h2>
          <p className="text-sm text-slate-500">Configure API keys, notifications, and platform preferences</p>
        </div>

        {/* API Keys */}
        <div className="stat-card">
          <div className="flex items-center gap-2 mb-4">
            <Key className="w-4 h-4 text-slate-400" />
            <h3 className="text-sm font-semibold text-slate-200">API Key Management</h3>
          </div>
          <div className="space-y-3">
            {API_KEYS.map(({ name, key, connected, icon }) => (
              <div key={name} className="flex items-center gap-3">
                <span className="text-xl w-7">{icon}</span>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-slate-300 mb-1">{name}</div>
                  <input
                    defaultValue={key}
                    placeholder={`Enter ${name} API key...`}
                    className="forensic-input text-xs py-1.5"
                    type="text"
                  />
                </div>
                <span className={`badge flex-shrink-0 ${connected ? "risk-safe" : "bg-white/5 text-slate-500"}`}>
                  {connected ? "✓ Connected" : "Not set"}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Notifications */}
        <div className="stat-card">
          <div className="flex items-center gap-2 mb-4">
            <Bell className="w-4 h-4 text-slate-400" />
            <h3 className="text-sm font-semibold text-slate-200">Notifications</h3>
          </div>
          <div className="space-y-3">
            {[
              { label: "Critical threat alerts", desc: "Notify immediately on critical IOC detection" },
              { label: "Case updates", desc: "Email when case status changes" },
              { label: "New IOC feed items", desc: "Daily digest of new threat intelligence" },
              { label: "Report generation complete", desc: "Notify when AI reports are ready" },
            ].map(({ label, desc }) => (
              <div key={label} className="flex items-center justify-between py-2 border-b border-white/[0.04]">
                <div>
                  <div className="text-sm text-slate-300">{label}</div>
                  <div className="text-xs text-slate-500">{desc}</div>
                </div>
                <div className="w-10 h-5 bg-cyan-500/30 rounded-full relative cursor-pointer flex items-center">
                  <div className="w-4 h-4 bg-cyan-400 rounded-full absolute right-0.5 shadow" />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* User */}
        <div className="stat-card">
          <div className="flex items-center gap-2 mb-4">
            <Users className="w-4 h-4 text-slate-400" />
            <h3 className="text-sm font-semibold text-slate-200">User Profile</h3>
          </div>
          <div className="flex items-center gap-4 mb-4">
            <div className="w-14 h-14 rounded-full bg-gradient-to-br from-cyan-500 to-violet-600 flex items-center justify-center text-white text-xl font-bold">A</div>
            <div>
              <div className="text-slate-200 font-medium">Admin User</div>
              <div className="text-xs text-slate-500">admin@forensix.ai</div>
              <span className="badge risk-safe text-xs mt-1">Senior Analyst</span>
            </div>
          </div>
          <div className="grid sm:grid-cols-2 gap-3">
            {[["Display Name", "Admin User"], ["Email", "admin@forensix.ai"], ["Role", "Senior Analyst"]].map(([k, v]) => (
              <div key={k}>
                <label className="text-xs text-slate-500 block mb-1">{k}</label>
                <input defaultValue={v} className="forensic-input text-xs py-2" />
              </div>
            ))}
          </div>
        </div>

        <button onClick={save} className="btn-primary">
          {saved ? <><Check className="w-4 h-4" />Saved!</> : <><Save className="w-4 h-4" />Save Settings</>}
        </button>
      </div>
    </AppLayout>
  );
}
