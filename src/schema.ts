import type { BetterAuthPluginDBSchema } from "@better-auth/core/db";

export const passwordPolicySchema = {
  user: {
    fields: {
      mustChangePassword: {
        type: "boolean",
        required: false,
        defaultValue: false,
        input: false,
      },
      passwordChangedAt: {
        type: "date",
        required: false,
        input: false,
      },
    },
  },
  passwordHistory: {
    fields: {
      userId: {
        type: "string",
        required: true,
        references: { model: "user", field: "id", onDelete: "cascade" },
        index: true,
      },
      passwordHash: {
        type: "string",
        required: true,
      },
      createdAt: {
        type: "date",
        required: true,
      },
    },
  },
  signInLockout: {
    fields: {
      identifier: {
        type: "string",
        required: true,
        unique: true,
      },
      failedAttempts: {
        type: "number",
        required: true,
        defaultValue: 0,
      },
      lockedUntil: {
        type: "date",
        required: false,
      },
      lastAttemptAt: {
        type: "date",
        required: true,
        index: true,
      },
    },
  },
} satisfies BetterAuthPluginDBSchema;

export type PasswordPolicySchema = typeof passwordPolicySchema;
