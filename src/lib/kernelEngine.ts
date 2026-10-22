import type { KernelSnapshot, TraceEntry } from "@/models/TraceLog";

export type SyscallName = "open" | "read" | "write" | "close" | "fork" | "getpid" | "brk" | "kill";
export type RegisterSet = { RAX: string; RDI: string; RSI: string; RDX: string; RIP: string; RSP: string; RFLAGS: string; PSW_MODE: "USER_RING_3" | "KERNEL_RING_0" };
export type Process = { pid: number; ppid: number; command: string; state: "RUNNING" | "TERMINATED"; uid: number };
export type FileNode = { path: string; inode: number; permissions: "READ_ONLY" | "READ_WRITE"; content: string };
export type Descriptor = { fd: number; path: string; inode: number | null; flags: string; offset: number; kind?: "stdio" };
export type MicroFrame = { step: number; title: string; zone: "USER" | "TRAP" | "KERNEL" | "RETURN"; detail: string; registers: RegisterSet };
export type KernelState = { registers: RegisterSet; pcbTable: Process[]; fdTable: Descriptor[]; vfsFiles: FileNode[]; traceLogs: TraceEntry[]; heapBreak: string; metrics: { totalSyscalls: number; ringTransitions: number; cpuCycles: number; failedCalls: number } };
export type ExecutionResult = { returnValue: string | number; errno: string | null; output?: string };

const syscallNumbers: Record<SyscallName, number> = { read: 0, write: 1, open: 2, close: 3, brk: 12, getpid: 39, fork: 57, kill: 62 };
const hex = (value: number) => `0x${value.toString(16).padStart(16, "0")}`;
const cleanArgs = (args: Record<string, unknown>) => Object.fromEntries(Object.entries(args).map(([key, value]) => [key, typeof value === "string" ? value : Number(value)]));

class VirtualKernel {
  private state: KernelState;
  private snapshots: KernelSnapshot[] = [];
  constructor() { this.state = this.boot(); }
  private boot(): KernelState {
    return {
      registers: { RAX: "0x0000000000000000", RDI: "0x0000000000000000", RSI: "0x0000000000000000", RDX: "0x0000000000000000", RIP: "0x0000000000401000", RSP: "0x00007fffffffe000", RFLAGS: "0x202", PSW_MODE: "USER_RING_3" },
      pcbTable: [{ pid: 1, ppid: 0, command: "systemd", state: "RUNNING", uid: 0 }, { pid: 1024, ppid: 1, command: "bash_user_app", state: "RUNNING", uid: 1000 }],
      fdTable: [{ fd: 0, path: "stdin", inode: null, flags: "O_RDONLY", offset: 0, kind: "stdio" }, { fd: 1, path: "stdout", inode: null, flags: "O_WRONLY", offset: 0, kind: "stdio" }, { fd: 2, path: "stderr", inode: null, flags: "O_WRONLY", offset: 0, kind: "stdio" }],
      vfsFiles: [{ path: "/etc/passwd", inode: 101, permissions: "READ_ONLY", content: "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/sh" }, { path: "/home/user/notes.txt", inode: 204, permissions: "READ_WRITE", content: "OS Mini Project: System Call Simulator\n" }, { path: "/var/log/syslog", inode: 309, permissions: "READ_WRITE", content: "[0.000000] Linux version 6.8.0-generic\n" }],
      traceLogs: [], heapBreak: "0x0000555555756000", metrics: { totalSyscalls: 0, ringTransitions: 0, cpuCycles: 0, failedCalls: 0 },
    };
  }
  public getState(): KernelState { return structuredClone(this.state); }
  public reset() { this.state = this.boot(); this.snapshots = []; return this.getState(); }
  private activePid() { return 1024; }
  private cloneRegs() { return structuredClone(this.state.registers); }
  private frame(step: number, title: string, zone: MicroFrame["zone"], detail: string): MicroFrame { return { step, title, zone, detail, registers: this.cloneRegs() }; }
  private loadArgs(name: SyscallName, args: Record<string, unknown>) {
    const value = (key: string, fallback = 0) => typeof args[key] === "number" ? args[key] as number : Number(args[key] ?? fallback) || fallback;
    const stringAddress = (key: string) => hex(0x7fffffffd000 + String(args[key] ?? "").length * 32);
    this.state.registers.RAX = hex(syscallNumbers[name]);
    this.state.registers.RDI = name === "open" ? stringAddress("pathname") : hex(value(name === "kill" ? "pid" : name === "brk" ? "incrementBytes" : "fd"));
    this.state.registers.RSI = name === "open" ? hex(value("flagsCode")) : name === "write" ? stringAddress("buffer") : hex(value(name === "kill" ? "sig" : "count"));
    this.state.registers.RDX = name === "write" ? hex(String(args.buffer ?? "").length) : "0x0000000000000000";
    this.state.registers.RIP = "0x0000000000401020";
  }
  private executeRoutine(name: SyscallName, args: Record<string, unknown>): ExecutionResult {
    const fd = Number(args.fd); const file = (path: string) => this.state.vfsFiles.find((entry) => entry.path === path);
    if (name === "open") {
      const pathname = String(args.pathname ?? ""); const flags = String(args.flags ?? "O_RDONLY"); let target = file(pathname);
      if (!target && flags.includes("O_CREAT")) { target = { path: pathname, inode: Math.max(...this.state.vfsFiles.map((entry) => entry.inode)) + 1, permissions: "READ_WRITE", content: "" }; this.state.vfsFiles.push(target); }
      if (!target) return { returnValue: -1, errno: "ENOENT" };
      if (target.permissions === "READ_ONLY" && (flags.includes("WRONLY") || flags.includes("RDWR"))) return { returnValue: -1, errno: "EACCES" };
      const newFd = Array.from({ length: 1024 }, (_, index) => index + 3).find((candidate) => !this.state.fdTable.some((entry) => entry.fd === candidate)) ?? -1;
      this.state.fdTable.push({ fd: newFd, path: target.path, inode: target.inode, flags, offset: 0 }); return { returnValue: newFd, errno: null };
    }
    if (name === "read") {
      const descriptor = this.state.fdTable.find((entry) => entry.fd === fd); if (!descriptor || descriptor.kind === "stdio") return { returnValue: -1, errno: "EBADF" };
      const target = file(descriptor.path); if (!target) return { returnValue: -1, errno: "EBADF" };
      const output = target.content.slice(descriptor.offset, descriptor.offset + Number(args.count ?? 64)); descriptor.offset += output.length; return { returnValue: output.length, errno: null, output };
    }
    if (name === "write") {
      const descriptor = this.state.fdTable.find((entry) => entry.fd === fd); if (!descriptor) return { returnValue: -1, errno: "EBADF" };
      const buffer = String(args.buffer ?? ""); if (descriptor.fd === 1) return { returnValue: buffer.length, errno: null, output: buffer };
      if (descriptor.flags === "O_RDONLY") return { returnValue: -1, errno: "EACCES" };
      const target = file(descriptor.path); if (!target) return { returnValue: -1, errno: "EBADF" }; if (target.permissions === "READ_ONLY") return { returnValue: -1, errno: "EACCES" };
      target.content += buffer; descriptor.offset += buffer.length; return { returnValue: buffer.length, errno: null };
    }
    if (name === "close") { const index = this.state.fdTable.findIndex((entry) => entry.fd === fd && fd >= 3); if (index < 0) return { returnValue: -1, errno: "EBADF" }; this.state.fdTable.splice(index, 1); return { returnValue: 0, errno: null }; }
    if (name === "fork") { const pid = Math.max(...this.state.pcbTable.map((process) => process.pid)) + 1; this.state.pcbTable.push({ pid, ppid: this.activePid(), command: "bash_user_app (child)", state: "RUNNING", uid: 1000 }); return { returnValue: pid, errno: null }; }
    if (name === "getpid") return { returnValue: this.activePid(), errno: null };
    if (name === "brk") { const next = Number.parseInt(this.state.heapBreak, 16) + Number(args.incrementBytes ?? 0); this.state.heapBreak = hex(next); return { returnValue: this.state.heapBreak, errno: null }; }
    const target = this.state.pcbTable.find((process) => process.pid === Number(args.pid)); if (!target) return { returnValue: -1, errno: "ESRCH" }; if (target.pid === 1) return { returnValue: -1, errno: "EPERM" }; target.state = "TERMINATED"; return { returnValue: 0, errno: null };
  }
  public execute(rawName: string, rawArgs: Record<string, unknown>) {
    const name = rawName as SyscallName; if (!(name in syscallNumbers)) throw new Error("Unsupported system call"); const args = cleanArgs(rawArgs);
    this.state.registers.PSW_MODE = "USER_RING_3";
    const frames = [this.frame(1, "User Space Wrapper", "USER", `libc invokes ${name}() from Ring 3.`)];
    this.loadArgs(name, args); frames.push(this.frame(2, "Register Loading", "USER", `RAX ← ${syscallNumbers[name]}; ABI arguments loaded into RDI, RSI, RDX.`));
    this.state.registers.PSW_MODE = "KERNEL_RING_0"; frames.push(this.frame(3, "Hardware Trap", "TRAP", "syscall instruction crosses the hardware privilege boundary."));
    frames.push(this.frame(4, "Syscall Dispatch", "KERNEL", `sys_call_table[${syscallNumbers[name]}] → sys_${name}`));
    const result = this.executeRoutine(name, args); frames.push(this.frame(5, "Kernel Routine & I/O", "KERNEL", result.errno ? `Kernel rejected request: ${result.errno}.` : `sys_${name} completed its kernel-side mutation.`));
    this.state.registers.RAX = result.errno ? `-${result.errno}` : typeof result.returnValue === "number" ? hex(result.returnValue) : result.returnValue; this.state.registers.PSW_MODE = "USER_RING_3"; this.state.registers.RIP = "0x0000000000401022";
    frames.push(this.frame(6, "sysret & Context Restore", "RETURN", `Return ${result.errno ? `-1 (${result.errno})` : result.returnValue} committed to RAX; resumed Ring 3.`));
    const traceEntry: TraceEntry = { timestamp: new Date().toISOString(), syscallName: name, syscallNumber: syscallNumbers[name], argsFormatted: this.formatArgs(name, args), returnValue: result.returnValue, errno: result.errno, durationUs: 84 + Math.floor(Math.random() * 240), ringTransitions: 2, pid: this.activePid() };
    this.state.traceLogs.unshift(traceEntry); this.state.metrics.totalSyscalls++; this.state.metrics.ringTransitions += 2; this.state.metrics.cpuCycles += 820 + Math.floor(Math.random() * 600); if (result.errno) this.state.metrics.failedCalls++;
    return { result, frames, state: this.getState(), traceEntry };
  }
  private formatArgs(name: SyscallName, args: Record<string, unknown>) { if (name === "open") return `\"${args.pathname}\", ${args.flags}`; if (name === "write") return `${args.fd}, \"${args.buffer}\", ${String(args.buffer ?? "").length}`; if (name === "read") return `${args.fd}, buf, ${args.count}`; if (name === "kill") return `${args.pid}, SIG${args.sig}`; return Object.values(args).join(", "); }
  public saveSnapshot(name: string): KernelSnapshot { const snapshot = { name, createdAt: new Date().toISOString(), pcbTable: structuredClone(this.state.pcbTable), fdTable: structuredClone(this.state.fdTable), vfsFiles: structuredClone(this.state.vfsFiles), traceHistory: structuredClone(this.state.traceLogs) }; this.snapshots = [snapshot, ...this.snapshots.filter((item) => item.name !== name)]; return snapshot; }
  public listSnapshots() { return structuredClone(this.snapshots); }
  public restoreSnapshotData(snapshot: KernelSnapshot) {
    this.state.pcbTable = structuredClone(snapshot.pcbTable) as Process[];
    this.state.fdTable = structuredClone(snapshot.fdTable) as Descriptor[];
    this.state.vfsFiles = structuredClone(snapshot.vfsFiles) as FileNode[];
    this.state.traceLogs = structuredClone(snapshot.traceHistory);
    this.snapshots = [structuredClone(snapshot), ...this.snapshots.filter((item) => item.name !== snapshot.name)];
    return this.getState();
  }
  public restoreSnapshot(name: string) { const snapshot = this.snapshots.find((item) => item.name === name); if (!snapshot) return null; this.state.pcbTable = structuredClone(snapshot.pcbTable) as Process[]; this.state.fdTable = structuredClone(snapshot.fdTable) as Descriptor[]; this.state.vfsFiles = structuredClone(snapshot.vfsFiles) as FileNode[]; this.state.traceLogs = structuredClone(snapshot.traceHistory); return this.getState(); }
}
export const kernelEngine = new VirtualKernel();
