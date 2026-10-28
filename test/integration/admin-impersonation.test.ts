import { describe, it, expect, afterEach } from "vitest";
import {
  createAuthRegistry,
  latestCookieHeadersFrom,
  expectForbidden,
} from "../harness/create-test-auth.ts";
import type { TestAuth } from "../harness/create-test-auth.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  await registry.closeAll();
});

const TWO_HOURS = 7200;

const impersonate = async (t: TestAuth, adminHeaders: Headers, userId: string) => {
  const result = await t.auth.api.impersonateUser({
    body: { userId },
    headers: adminHeaders,
    returnHeaders: true,
  });
  return latestCookieHeadersFrom(result.headers);
};

describe("stopping impersonation of a user who must change the password", () => {
  it("lets the admin stop impersonating a flagged user while other routes stay blocked", async () => {
    const t = await open();
    const target = await t.signUp();
    const admin = await t.createAdmin();
    const impersonationHeaders = await impersonate(t, admin.headers, target.id);
    await t.auth.api.setPasswordChangeRequired({ body: { userId: target.id, required: true } });
    await expectForbidden(
      () => t.auth.api.listSessions({ headers: impersonationHeaders }),
      "PASSWORD_CHANGE_REQUIRED",
    );
    const result = await t.auth.api.stopImpersonating({ headers: impersonationHeaders });
    expect(result.user.id).toBe(admin.id);
  });

  it("lets the admin stop impersonating a user whose password has expired", async () => {
    const t = await open({ policy: { expiration: { maxAge: 3600 } } });
    const target = await t.signUp();
    const admin = await t.createAdmin();
    const impersonationHeaders = await impersonate(t, admin.headers, target.id);
    await t.backdatePassword(target.id, TWO_HOURS);
    await expectForbidden(
      () => t.auth.api.listSessions({ headers: impersonationHeaders }),
      "PASSWORD_EXPIRED",
    );
    const result = await t.auth.api.stopImpersonating({ headers: impersonationHeaders });
    expect(result.user.id).toBe(admin.id);
  });
});
