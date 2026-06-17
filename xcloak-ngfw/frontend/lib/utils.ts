import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(d: string | null | undefined): string {
  if (!d) return '—';
  const dt = new Date(d);
  if (isNaN(dt.getTime())) return '—';
  return dt.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });
}

export function timeAgo(d: string | null | undefined): string {
  if (!d) return '—';
  const s = Math.floor((Date.now() - new Date(d).getTime()) / 1000);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function sevClass(s: string) {
  switch (s?.toLowerCase()) {
    case 'critical': return 'sev-critical';
    case 'high':     return 'sev-high';
    case 'medium':   return 'sev-medium';
    case 'low':      return 'sev-low';
    default:         return 'sev-info';
  }
}

export function sevDot(s: string) {
  switch (s?.toLowerCase()) {
    case 'critical': return 'dot-critical';
    case 'high':     return 'dot-high';
    case 'medium':   return 'dot-medium';
    default:         return 'dot-low';
  }
}

// Keep old names for backward compat
export const getSeverityClass  = sevClass;
export const getSeverityColor  = sevClass;
export const getStatusColor    = (s: string) => s === 'online' ? 'sev-low' : 'sev-info';
export const getStatusClass    = getStatusColor;
export const severityDot       = sevDot;

// Risk score helpers (risk is a 0–100 number).
export function getRiskLevel(risk: number): string {
  if (risk >= 80) return 'Critical';
  if (risk >= 60) return 'High';
  if (risk >= 40) return 'Medium';
  return 'Low';
}

export function getRiskColor(risk: number): string {
  if (risk >= 80) return 'text-red-600';
  if (risk >= 60) return 'text-orange-600';
  if (risk >= 40) return 'text-yellow-600';
  return 'text-green-600';
}
