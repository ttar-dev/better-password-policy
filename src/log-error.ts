import { readString, toRecord } from "./record.ts";

export type ErrorSummary = {
  name: string | null;
  code: string | null;
  cause?: ErrorSummary;
};

const MAX_CAUSE_DEPTH = 3;

export const summarizeError = (error: unknown, depth = 0): ErrorSummary => {
  const fields = toRecord(error);
  const summary: ErrorSummary = {
    name: error instanceof Error ? error.name : readString(fields, "name"),
    code: readString(fields, "code"),
  };
  const cause = error instanceof Error ? error.cause : fields.cause;
  if (depth < MAX_CAUSE_DEPTH && cause !== undefined && cause !== null) {
    summary.cause = summarizeError(cause, depth + 1);
  }
  return summary;
};
