export const toRecord = (value: unknown): Record<string, unknown> =>
  typeof value === "object" && value !== null ? Object.fromEntries(Object.entries(value)) : {};

export const readString = (record: Record<string, unknown>, key: string): string | null => {
  const value = record[key];
  return typeof value === "string" ? value : null;
};

export const readNonEmptyString = (record: Record<string, unknown>, key: string): string | null => {
  const value = readString(record, key);
  return value === null || value === "" ? null : value;
};
