import mongoose from "mongoose";

declare global {
  var mongooseConnection: Promise<typeof mongoose> | undefined;
  var isUsingMemoryFallback: boolean | undefined;
}

export function usingMemoryFallback() {
  return global.isUsingMemoryFallback ?? true;
}

export async function connectToDatabase(): Promise<typeof mongoose | null> {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    global.isUsingMemoryFallback = true;
    return null;
  }
  try {
    if (!global.mongooseConnection) {
      global.mongooseConnection = mongoose.connect(uri, { serverSelectionTimeoutMS: 1500 });
    }
    const connection = await global.mongooseConnection;
    global.isUsingMemoryFallback = false;
    return connection;
  } catch {
    global.mongooseConnection = undefined;
    global.isUsingMemoryFallback = true;
    return null;
  }
}
