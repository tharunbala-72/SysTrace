"use client";

import { Database, RotateCcw, Save } from "lucide-react";
import type { KernelState } from "@/lib/kernelEngine";

type Props = { state: KernelState | null; dbStatus: string; onReset: () => void; onPreset: (preset: string) => void; onSnapshot: () => void };

export function TopHeaderBar({ state, dbStatus, onReset, onPreset, onSnapshot }: Props) {
  const kernel = state?.registers.PSW_MODE === "KERNEL_RING_0";
  return <header className="topbar"><div className="brand"><span className="brand-dot"/><div><strong>SYSTRACE</strong><span>{"// OS KERNEL WORKBENCH"}</span></div></div><div className="top-actions"><span className={`status-badge ${kernel ? "kernel" : "user"}`}>{kernel ? "RING 0 · KERNEL MODE" : "RING 3 · USER MODE"}</span><span className="status-badge database"><Database size={16}/>{dbStatus === "connected" ? "MongoDB Connected" : "In-Memory Engine"}</span><select aria-label="Preset pipeline" defaultValue="" onChange={(event) => { if (event.target.value) onPreset(event.target.value); event.currentTarget.value = ""; }}><option value="" disabled>Run guided preset…</option><option value="file">File I/O · Open → Write → Read → Close</option><option value="process">Process lifecycle · Fork → GetPID → Kill</option><option value="errors">Error traps · EBADF & EACCES</option></select><button onClick={onSnapshot}><Save size={16}/> Snapshot</button><button className="reset-button" onClick={onReset}><RotateCcw size={16}/> Reset kernel</button></div></header>;
}
