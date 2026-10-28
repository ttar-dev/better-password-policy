# @ttar-dev/better-password-policy

Password complexity, password history, password expiry, forced password change and sign-in lockout for [Better Auth](https://better-auth.com).

Requires `better-auth` and `@better-auth/core` `>=1.7.12 <1.8.0`, and `zod` `^4.5.4`. The plugin depends on the exact list of password-setting endpoints of Better Auth 1.7, so the peer range stops at the next minor on purpose: a new minor could add an endpoint that would silently skip the policy.

## Install

| Package manager | Command |
| --- | --- |
| npm | `npm install @ttar-dev/better-password-policy` |
| Bun | `bun add @ttar-dev/better-password-policy` |
| pnpm | `pnpm add @ttar-dev/better-password-policy` |
| Yarn | `yarn add @ttar-dev/better-password-policy` |

## Setup

Server:

```ts
import { betterAuth } from "better-auth";
import { passwordPolicy } from "@ttar-dev/better-password-policy";

export const auth = betterAuth({
  emailAndPassword: { enabled: true },
  plugins: [
    passwordPolicy({
      complexity: { requireSymbol: true },
      history: { count: 5 },
      expiration: { maxAge: 60 * 60 * 24 * 90 },
      lockout: { maxAttempts: 5, duration: 900 },
    }),
  ],
});
```

Client:

```ts
import { createAuthClient } from "better-auth/client";
import { passwordPolicyClient } from "@ttar-dev/better-password-policy/client";

export const authClient = createAuthClient({
  plugins: [passwordPolicyClient()],
});
```

## Database schema

The plugin adds two columns to `user` (`mustChangePassword`, `passwordChangedAt`) and two tables (`passwordHistory`, `signInLockout`). Regenerate your schema and migrate:

| Package manager | Command |
| --- | --- |
| npm | `npx auth@latest generate` |
| Bun | `bunx auth@latest generate` |
| pnpm | `pnpm dlx auth@latest generate` |
| Yarn | `yarn dlx auth@latest generate` |

Then pass the generated schema to your adapter, for example with Drizzle:

```ts
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import * as schema from "./auth-schema";

database: drizzleAdapter(db, { provider: "pg", schema })
```

Table and field names can be changed with the `schema` option, for example `passwordPolicy({ schema: { passwordHistory: { modelName: "pw_history" } } })`.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `complexity` | `{ requireUppercase: true, requireLowercase: true, requireDigit: true, requireSymbol: false, rejectPersonalInfo: true }` | Partial objects are filled from the defaults. `false` disables complexity, personal info and `validate` checks on every path. Better Auth min and max length still apply. |
| `complexity.validate` | none | `({ password, user: { id, email, name } }) => boolean \| Promise<boolean>`. Return `false` to reject with `PASSWORD_REJECTED`. `user.id` is `null` while the user does not exist yet. |
| `history` | `{ count: 5 }` | Rejects the current password and the previous `count` passwords, and keeps `count + 1` rows per user. `count: 0` rejects only the current password. `false` disables the reuse check and writes no rows. |
| `expiration` | off | `{ maxAge }` in seconds, must be greater than 0. A password older than `maxAge` blocks authenticated routes until it is changed. `false` or omitted: `passwordChangedAt` is still recorded but the password never expires. |
| `lockout` | `{ maxAttempts: 5, duration: 900 }` | Seconds for `duration`. `false` registers no sign-in hooks and writes no rows. |
| `schema` | none | Rename models and fields. |

Forced password change has no option: it is always available and has no effect until the application sets the flag.

Invalid values throw a `TypeError` starting with `password-policy:` when the plugin is created.

Complexity checks run in this order and the first failure wins: uppercase, lowercase, digit, symbol, personal info, `validate`, history. Letters and digits are Unicode aware, a space counts as a symbol. Personal info tokens come from the email local part and the name (lowercased, split on non letters and digits, tokens of at least 3 characters); the password is rejected if it contains any token. The email domain is not used.

Where the policy is enforced: `/sign-up/email`, `/change-password`, `/reset-password`, `/email-otp/reset-password`, `/phone-number/reset-password`, `/admin/set-user-password`, `/admin/create-user` (complexity only) and the server-only `auth.api.setPassword`. Sign-in never runs complexity or history checks.

## Error codes

All errors are `APIError`s whose `body.code` is the key below. The codes are exported as `PASSWORD_POLICY_ERROR_CODES` from both `@ttar-dev/better-password-policy` and `@ttar-dev/better-password-policy/client`.

| Code | Status | Message |
| --- | --- | --- |
| `PASSWORD_MISSING_UPPERCASE` | 400 | Password must contain at least one uppercase letter |
| `PASSWORD_MISSING_LOWERCASE` | 400 | Password must contain at least one lowercase letter |
| `PASSWORD_MISSING_DIGIT` | 400 | Password must contain at least one digit |
| `PASSWORD_MISSING_SYMBOL` | 400 | Password must contain at least one symbol |
| `PASSWORD_CONTAINS_PERSONAL_INFO` | 400 | Password must not contain your name or email |
| `PASSWORD_REJECTED` | 400 | Password does not meet the password policy |
| `PASSWORD_REUSED` | 400 | Password was used recently, choose a different password |
| `PASSWORD_CHANGE_REQUIRED` | 403 | Password change required |
| `PASSWORD_EXPIRED` | 403 | Password expired, change it to continue |
| `SIGN_IN_LOCKED` | 429 | Too many failed sign-in attempts, try again later |

## Server-only endpoints

The plugin has no HTTP routes. These endpoints exist only on `auth.api` so that no request from a browser can unlock an account or flag a user:

| Endpoint | Input | Result |
| --- | --- | --- |
| `auth.api.setPasswordChangeRequired` | `body: { userId, required }` | `{ status: true }` |
| `auth.api.unlockSignIn` | `body: { userId }` | `{ status: true }` |
| `auth.api.getPasswordPolicyStatus` | `query: { userId }` | `{ mustChangePassword, passwordChangedAt, passwordExpiresAt, passwordChangeRequirement, lockedUntil, failedSignInAttempts }` |

An unknown `userId` fails with 404 `USER_NOT_FOUND`.

The plugin does not decide who may call them. Check authorization yourself first, for example with the admin plugin:

```ts
import { APIError } from "better-auth/api";

export async function forcePasswordChange(headers: Headers, userId: string) {
  const permission = await auth.api.userHasPermission({
    headers,
    body: { permissions: { user: ["set-password"] } },
  });
  if (!permission.success) {
    throw new APIError("FORBIDDEN");
  }
  return auth.api.setPasswordChangeRequired({ body: { userId, required: true } });
}
```

## Forced change and expiry

`mustChangePassword` and `passwordChangedAt` are returned on the session user. While a change is required, every authenticated route that has an HTTP path answers 403 `PASSWORD_CHANGE_REQUIRED` (flag) or `PASSWORD_EXPIRED` (age). If both apply, the flag wins. Routes needed to recover stay open: `/change-password`, `/sign-out`, `/get-session`, `/admin/stop-impersonating`, the sign-in, sign-up, password reset, email verification and OTP routes. The full list is exported as `PASSWORD_CHANGE_EXEMPT_PATHS`. Server-only endpoints (no HTTP path) are never gated.

The gate checks these sessions: the session cookie, the `Authorization: Bearer <token>` session that the `bearer()` plugin derives (listed before or after `passwordPolicy()`), and a session that a hook running before `passwordPolicy()` already loaded. If any of them belongs to a user who must change the password, the request is blocked, even when Better Auth would act as the other user. A client that sends one user's cookie together with another user's bearer token must stop sending the cookie (for example `credentials: "omit"`), or that user must change the password using the cookie alone. This applies to `auth.handler` and `auth.api.*` calls. Not covered: a before-hook other than `bearer()` that rewrites request headers to switch the session (including your own `hooks.before`), a before-hook listed after `passwordPolicy()` that sets the session directly (for example `apiKey` sessions), `multiSession` inactive sessions (the `_multi-*` cookies), and the impersonating admin's own session (the `admin_session` cookie). List plugins that set the session directly before `passwordPolicy()`.

Changing the password through any covered path sets `passwordChangedAt` and clears the flag, except `/admin/create-user` and `/admin/set-user-password`, which set a temporary password and keep the flag.

Gate your own routes or pages with the pure helper, which is also exported from `@ttar-dev/better-password-policy/client`:

```ts
import { getPasswordChangeRequirement } from "@ttar-dev/better-password-policy/client";

const requirement = getPasswordChangeRequirement(session.user, maxAgeSeconds);
if (requirement === "forced" || requirement === "expired") {
  redirect("/change-password");
}
```

`getPasswordExpiresAt(passwordChangedAt, maxAgeSeconds)` returns the expiry date or `null`. A password is expired exactly at `passwordChangedAt + maxAge`.

Existing users have `passwordChangedAt = null` and are never treated as expired. To start their clock, backfill after migrating:

```sql
update "user" set password_changed_at = now() where password_changed_at is null;
```

Cookie cache: with `session.cookieCache` enabled, the session user inside the cookie can be stale. A flag or expiry that is set after sign-in takes effect only after the cookie cache expires (`cookieCache.maxAge`), because a cached "no change required" is trusted. A cached "change required" is re-checked against the database, so changing the password unblocks the user immediately.

## Sign-in lockout

Failed attempts are counted per identifier (`email:<lowercase email>`, `username:<normalized username>`, `phone:<phone number>`) on `/sign-in/email`, `/sign-in/username` and `/sign-in/phone-number`. Every sign-in attempt that does not present the correct password counts, including malformed input, unknown accounts and any error response. After `maxAttempts` such attempts the identifier is locked for `duration` seconds and further sign-ins answer 429 `SIGN_IN_LOCKED` without checking the password. Presenting the correct password always resets the counter, whatever the response is afterwards (success, two-factor, unverified email, banned user, or a response rewritten by another hook); the plugin decides this from the password verification itself, not from the response. Resetting the password and `auth.api.unlockSignIn` also delete the user's rows. Counting is atomic: an attempt is reserved before the password is verified, so concurrent requests cannot verify more than `maxAttempts` passwords per lock window.

Behavior to know about:

- Counting is keyed by the identifier string, not by user, so identifiers that do not belong to any account lock exactly like real ones. The 429 therefore reveals only that this string had too many attempts, which the caller caused. It does not reveal whether an account exists.
- A user who can sign in with email, username and phone gets up to `3 * maxAttempts` attempts, because the three identifiers are counted separately. Locking one identifier does not lock the others.
- Anyone can lock any identifier by failing sign-ins for it. This is inherent to account lockout. Combine with IP rate limiting.
- The correct password with an error that is not about the password (banned user, unverified email, two-factor required) resets the counter and is never counted. Requests that never reach password verification (validation errors, unknown account, account without a password, an unverified phone number when the phoneNumber plugin has `requireVerification`) are counted.
- Rows for identifiers that never succeed accumulate. Clean them up periodically:

```sql
delete from sign_in_lockout
where (locked_until is null or locked_until < now())
  and last_attempt_at < now() - interval '30 days';
```

## Plugin order

Put any plugin whose before-hook can reject or short-circuit a sign-in (for example `captcha`) before `passwordPolicy` in the `plugins` array. The lockout reserves an attempt in its before-hook and clears it in its after-hook only when the correct password was verified, so a request rejected by a before-hook that runs after `passwordPolicy` also counts as a failed attempt.

`passwordPolicy` works in any order relative to `twoFactor` and `haveIBeenPwned`.

## Limitations

- Password writes made by calling `internalAdapter.updatePassword` or `internalAdapter.updateAccount` directly, outside an endpoint, are not recorded in the history and do not update `passwordChangedAt`. Account creation is always recorded.
- Password-setting endpoints added by third-party plugins are not covered by the policy.
- If recording fails after the password was already changed, the error is logged and the request still succeeds; that password can then be reused later.
- `/admin/create-user` is checked before the admin plugin authorizes the request, so an unauthenticated caller can learn the complexity rules (they are not secret). Better Auth does not enforce a minimum length there.
- With `/email-otp/reset-password`, Better Auth consumes the OTP up front only when it does not match. A valid OTP stays usable after the policy rejects the new password, so the user can retry with a stronger one.
- An admin session impersonating a flagged user is gated like that user, except `/admin/stop-impersonating`, which stays open.
- The server-only `auth.api.setPassword` answers 400 `PASSWORD_ALREADY_SET` for any password when the user already has one, exactly like Better Auth, and applies the policy only when the user has no password yet.
