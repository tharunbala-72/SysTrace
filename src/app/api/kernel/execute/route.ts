import { NextResponse } from "next/server";
import { connectToDatabase } from "@/lib/mongodb";
import { kernelEngine } from "@/lib/kernelEngine";
import { TraceLog } from "@/models/TraceLog";

export async function POST(request: Request) {
  try {
    const body = await request.json() as { syscall?: string; args?: Record<string, unknown> };
    if (!body.syscall) return NextResponse.json({ success: false, error: "syscall is required" }, { status: 400 });
    const execution = kernelEngine.execute(body.syscall, body.args ?? {});
    if (await connectToDatabase()) await TraceLog.create(execution.traceEntry);
    return NextResponse.json({ success: true, ...execution });
  } catch (error) {
    return NextResponse.json({ success: false, error: error instanceof Error ? error.message : "Execution failed" }, { status: 400 });
  }
}
