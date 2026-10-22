import { NextResponse } from "next/server";
import { connectToDatabase } from "@/lib/mongodb";
import { kernelEngine } from "@/lib/kernelEngine";
import { Snapshot } from "@/models/TraceLog";

export async function GET() {
  const connected = await connectToDatabase();
  const snapshots = connected ? await Snapshot.find().sort({ createdAt: -1 }).lean() : kernelEngine.listSnapshots();
  return NextResponse.json({ snapshots });
}
export async function POST(request: Request) {
  const body = await request.json() as { action?: "save" | "restore"; name?: string };
  if (!body.name) return NextResponse.json({ success: false, error: "Snapshot name is required" }, { status: 400 });
  if (body.action === "restore") {
    let state = kernelEngine.restoreSnapshot(body.name);
    if (!state && await connectToDatabase()) {
      const snapshot = await Snapshot.findOne({ name: body.name }).lean();
      if (snapshot) state = kernelEngine.restoreSnapshotData({ name: snapshot.name, createdAt: snapshot.createdAt, pcbTable: snapshot.pcbTable, fdTable: snapshot.fdTable, vfsFiles: snapshot.vfsFiles, traceHistory: snapshot.traceHistory });
    }
    return state ? NextResponse.json({ success: true, state }) : NextResponse.json({ success: false, error: "Snapshot not found" }, { status: 404 });
  }
  const snapshot = kernelEngine.saveSnapshot(body.name);
  if (await connectToDatabase()) await Snapshot.findOneAndUpdate({ name: snapshot.name }, snapshot, { upsert: true });
  return NextResponse.json({ success: true, snapshot });
}
