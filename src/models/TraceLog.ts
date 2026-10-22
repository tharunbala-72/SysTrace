import { Schema, model, models, type Model } from "mongoose";

export interface TraceEntry {
  timestamp: string;
  syscallName: string;
  syscallNumber: number;
  argsFormatted: string;
  returnValue: string | number;
  errno: string | null;
  durationUs: number;
  ringTransitions: number;
  pid: number;
}

export interface KernelSnapshot {
  name: string;
  createdAt: string;
  pcbTable: unknown[];
  fdTable: unknown[];
  vfsFiles: unknown[];
  traceHistory: TraceEntry[];
}

const traceEntrySchema = new Schema<TraceEntry>({
  timestamp: String, syscallName: String, syscallNumber: Number, argsFormatted: String,
  returnValue: Schema.Types.Mixed, errno: { type: String, default: null }, durationUs: Number,
  ringTransitions: Number, pid: Number,
}, { _id: false });

const snapshotSchema = new Schema<KernelSnapshot>({
  name: { type: String, required: true }, createdAt: { type: String, required: true },
  pcbTable: [Schema.Types.Mixed], fdTable: [Schema.Types.Mixed], vfsFiles: [Schema.Types.Mixed],
  traceHistory: [traceEntrySchema],
});

export const TraceLog: Model<TraceEntry> = (models.TraceLog as Model<TraceEntry>) || model<TraceEntry>("TraceLog", traceEntrySchema);
export const Snapshot: Model<KernelSnapshot> = (models.Snapshot as Model<KernelSnapshot>) || model<KernelSnapshot>("Snapshot", snapshotSchema);
