import { NextResponse } from "next/server";
import { kernelEngine } from "@/lib/kernelEngine";
export async function POST() { return NextResponse.json({ success: true, state: kernelEngine.reset() }); }
