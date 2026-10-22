import { NextResponse } from "next/server";
import { connectToDatabase, usingMemoryFallback } from "@/lib/mongodb";
import { kernelEngine } from "@/lib/kernelEngine";

export async function GET() {
  await connectToDatabase();
  return NextResponse.json({ state: kernelEngine.getState(), dbStatus: usingMemoryFallback() ? "memory" : "connected" });
}
