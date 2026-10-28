import type { AuthEndpointContext } from "@better-auth/core/context";
import { readString, toRecord } from "./record.ts";

export const POLICY_ENFORCED_PATHS: readonly string[] = [
  "/sign-up/email",
  "/change-password",
  "/reset-password",
  "/email-otp/reset-password",
  "/phone-number/reset-password",
  "/admin/set-user-password",
];

export const SET_PASSWORD_OPERATION_ID = "setPassword";

export const ADMIN_PASSWORD_PATHS: readonly string[] = ["/admin/create-user", "/admin/set-user-password"];

export type PasswordTarget =
  | { kind: "new-user"; email: string | null; name: string | null }
  | {
      kind: "existing-user";
      userId: string;
      email: string | null;
      name: string | null;
      currentPasswordHash: string | null;
    }
  | { kind: "unauthorized" };

interface TargetUser {
  id: string;
  email: string;
  name: string;
}

const unresolvedUser: PasswordTarget = { kind: "new-user", email: null, name: null };

export const isPolicedPasswordContext = (c: AuthEndpointContext | undefined): c is AuthEndpointContext => {
  if (c === undefined) {
    return false;
  }
  if (c.path !== undefined && POLICY_ENFORCED_PATHS.includes(c.path)) {
    return true;
  }
  return "operationId" in c && c.operationId === SET_PASSWORD_OPERATION_ID;
};

const toExistingUser = async (c: AuthEndpointContext, user: TargetUser): Promise<PasswordTarget> => {
  const account = await c.context.internalAdapter.findCredentialAccount(user.id);
  return {
    kind: "existing-user",
    userId: user.id,
    email: user.email,
    name: user.name,
    currentPasswordHash: account?.password || null,
  };
};

const resolveSetPasswordTarget = async (c: AuthEndpointContext): Promise<PasswordTarget> => {
  const sessionUser = c.context.session?.user;
  if (!sessionUser) {
    return { kind: "unauthorized" };
  }
  const account = await c.context.internalAdapter.findCredentialAccount(sessionUser.id);
  if (account?.password) {
    return { kind: "unauthorized" };
  }
  return toExistingUser(c, sessionUser);
};

const resolveChangePasswordTarget = async (c: AuthEndpointContext): Promise<PasswordTarget> => {
  const sessionUser = c.context.session?.user;
  const currentPassword = readString(toRecord(c.body), "currentPassword");
  if (!sessionUser || currentPassword === null) {
    return { kind: "unauthorized" };
  }
  const account = await c.context.internalAdapter.findCredentialAccount(sessionUser.id);
  if (!account?.password) {
    return { kind: "unauthorized" };
  }
  const matches = await c.context.password.verify({ hash: account.password, password: currentPassword });
  if (!matches) {
    return { kind: "unauthorized" };
  }
  return {
    kind: "existing-user",
    userId: sessionUser.id,
    email: sessionUser.email,
    name: sessionUser.name,
    currentPasswordHash: account.password,
  };
};

const resolveResetPasswordTarget = async (c: AuthEndpointContext): Promise<PasswordTarget> => {
  const token = readString(toRecord(c.body), "token") || readString(toRecord(c.query), "token");
  if (!token) {
    return unresolvedUser;
  }
  const verification = await c.context.internalAdapter.findVerificationValue(`reset-password:${token}`);
  if (!verification) {
    return unresolvedUser;
  }
  const user = await c.context.internalAdapter.findUserById(verification.value);
  return user ? toExistingUser(c, user) : unresolvedUser;
};

const resolveEmailOtpTarget = async (c: AuthEndpointContext): Promise<PasswordTarget> => {
  const email = readString(toRecord(c.body), "email");
  if (email === null) {
    return unresolvedUser;
  }
  const found = await c.context.internalAdapter.findUserByEmail(email.toLowerCase());
  return found ? toExistingUser(c, found.user) : unresolvedUser;
};

const resolvePhoneNumberTarget = async (c: AuthEndpointContext): Promise<PasswordTarget> => {
  const phoneNumber = readString(toRecord(c.body), "phoneNumber");
  if (phoneNumber === null) {
    return unresolvedUser;
  }
  const user = await c.context.adapter.findOne<TargetUser>({
    model: "user",
    where: [{ field: "phoneNumber", value: phoneNumber }],
  });
  return user ? toExistingUser(c, user) : unresolvedUser;
};

const resolveAdminSetPasswordTarget = async (c: AuthEndpointContext): Promise<PasswordTarget> => {
  const userId = readString(toRecord(c.body), "userId");
  if (userId === null) {
    return unresolvedUser;
  }
  const user = await c.context.internalAdapter.findUserById(userId);
  return user ? toExistingUser(c, user) : unresolvedUser;
};

const resolveSignUpTarget = (c: AuthEndpointContext): PasswordTarget => {
  const body = toRecord(c.body);
  return { kind: "new-user", email: readString(body, "email"), name: readString(body, "name") };
};

export const resolvePasswordTarget = async (c: AuthEndpointContext): Promise<PasswordTarget> => {
  switch (c.path) {
    case "/sign-up/email":
      return resolveSignUpTarget(c);
    case "/change-password":
      return resolveChangePasswordTarget(c);
    case "/reset-password":
      return resolveResetPasswordTarget(c);
    case "/email-otp/reset-password":
      return resolveEmailOtpTarget(c);
    case "/phone-number/reset-password":
      return resolvePhoneNumberTarget(c);
    case "/admin/set-user-password":
      return resolveAdminSetPasswordTarget(c);
    default:
      return resolveSetPasswordTarget(c);
  }
};
