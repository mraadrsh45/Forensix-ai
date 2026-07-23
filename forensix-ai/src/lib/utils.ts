import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(date: string | Date) {
  return new Date(date).toLocaleDateString("en-US", {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

export function getRiskColor(score: number) {
  if (score >= 80) return "text-red-400";
  if (score >= 60) return "text-orange-400";
  if (score >= 40) return "text-yellow-400";
  return "text-emerald-400";
}

export function getRiskLabel(score: number) {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 40) return "Medium";
  if (score >= 20) return "Low";
  return "Safe";
}

export function getRiskBg(score: number) {
  if (score >= 80) return "bg-red-500/20 border-red-500/50";
  if (score >= 60) return "bg-orange-500/20 border-orange-500/50";
  if (score >= 40) return "bg-yellow-500/20 border-yellow-500/50";
  return "bg-emerald-500/20 border-emerald-500/50";
}

export function truncate(str: string, n: number) {
  return str.length > n ? str.slice(0, n) + "…" : str;
}
