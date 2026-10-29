# @ttar-dev/better-password-policy

Password complexity, password history, password expiry, forced password change and sign-in lockout for [Better Auth](https://better-auth.com), with optional per-tenant overrides that can only tighten the platform policy.

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

`signInLockout.lastAttemptAt` is indexed since 1.2.0, so the retention purge does not scan the table. Better Auth only checks that tables and columns exist, so a database without the index keeps working, only slower.

## Upgrading to 1.2.0

Regenerate your schema and migrate to add the index on `signInLockout.lastAttemptAt`.

The `identifier` column of `signInLockout` no longer holds readable values. Rows written by an earlier version (`email:...`, `username:...`, `phone:...`) never match again: every counter restarts once and identifiers that are locked when you deploy are released. Delete the old rows, because they still contain personal data. During a rolling deploy, 1.0 and 1.2 instances keep separate counters (up to `2 * maxAttempts` per lock window until the rollout finishes), so run this SQL after every instance runs 1.2.0. Legacy rows are also purged automatically within `retention`.

```sql
delete from sign_in_lockout
where identifier like 'email:%' or identifier like 'username:%' or identifier like 'phone:%';
```

Sign-in responses now set a device cookie after a verified password. Set `lockout: { deviceCookie: false }` to opt out. Rows older than `lockout.retention` (30 days by default) are now deleted automatically, see [Sign-in lockout](#sign-in-lockout).

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `complexity` | `{ requireUppercase: true, requireLowercase: true, requireDigit: true, requireSymbol: false, rejectPersonalInfo: true, caselessLettersSatisfyCase: false }` | Partial objects are filled from the defaults. `false` disables the minimum length, complexity, personal info and `validate` checks on every path. Better Auth min and max length still apply. |
| `complexity.minLength` | none | Integer from 1 to 128, counted in UTF-16 code units like Better Auth's own minimum. Shorter passwords answer 400 `PASSWORD_TOO_SHORT` (Better Auth's code), also on `/admin/create-user`. Keep it at or below Better Auth's `maxPasswordLength`, otherwise no password can be set. |
| `complexity.caselessLettersSatisfyCase` | `false` | When `true`, a password with at least one caseless letter (Unicode `Lo` outside the Latin and Common scripts, for example Thai, Hebrew, Arabic or CJK letters; `º`, `ª` and other Latin `Lo` characters do not count) satisfies both `requireUppercase` and `requireLowercase`. Passwords without a caseless letter are judged as before. One caseless letter is enough, so pair it with `minLength`. A tenant can only turn it off. |
| `complexity.validate` | none | `({ password, user: { id, email, name } }) => boolean \| Promise<boolean>`. Return `false` to reject with `PASSWORD_REJECTED`. `user.id` is `null` while the user does not exist yet. |
| `history` | `{ count: 5 }` | Rejects the current password and the previous `count` passwords, and keeps `count + 1` rows per user. `count: 0` rejects only the current password. `false` disables the reuse check and writes no rows. |
| `expiration` | off | `{ maxAge }` in seconds, must be greater than 0. A password older than `maxAge` blocks authenticated routes until it is changed. Omitted: no platform limit, `passwordChangedAt` is still recorded and a tenant may set `maxAge`. `false`: passwords never expire, for every tenant. `{ maxAge }`: floor for every tenant, a tenant can only shorten it. Without `tenantPolicy`, omitted and `false` behave the same. |
| `lockout` | `{ maxAttempts: 5, duration: 900, retention: 2592000, deviceCookie: { maxAge: 2592000 } }` | Seconds for `duration`. `false` registers no sign-in hooks, writes no rows, sets no cookie and runs no purge. |
| `lockout.retention` | `2592000` | Seconds, an integer from 86400 to 315360000. Lockout rows whose last attempt is older than this and that are not locked are deleted automatically. `false` disables the purge. Platform-only: a tenant cannot set it. |
| `lockout.deviceCookie` | `{ maxAge: 2592000 }` | `maxAge` in seconds, an integer from 1 to 34560000. After a verified password the response sets a signed device cookie that gives the browser its own attempt counter. `false` never reads or sets the cookie. Platform-only: a tenant cannot set it. |
| `tenantPolicy` | none | `(context) => override \| null \| undefined \| Promise<...>`. Returns a per-tenant override that can only tighten the options above. See [Per-tenant policy](#per-tenant-policy). |
| `schema` | none | Rename models and fields. |

Forced password change has no option: it is always available and has no effect until the application sets the flag.

Invalid values throw a `TypeError` starting with `password-policy:` when the plugin is created, including a `tenantPolicy` that is not a function, a `complexity.minLength` outside 1 to 128, a `lockout.retention` outside 86400 to 315360000, and a `lockout.deviceCookie.maxAge` outside 1 to 34560000.

Complexity checks run in this order and the first failure wins: minimum length, uppercase, lowercase, digit, symbol, personal info, `validate`, history. Letters, combining marks and digits are Unicode aware: a nonspacing or spacing combining mark (`Mn`, `Mc`, for example a Thai vowel or tone mark, or an accent) is never a symbol, while a space and an enclosing mark (`Me`, for example the keycap in `1️⃣`) count as symbols. Personal info tokens come from the email local part and the name (lowercased, normalized to NFC with `İ` folded to `i`, the same as the password, split on characters that are not letters, nonspacing or spacing marks, or digits, tokens of at least 3 code points, marks included); the password is rejected if it contains any token. The email domain is not used. Names written in Thai and other scripts that use combining marks are matched whole.

Since 1.2.0, nonspacing and spacing combining marks no longer count as symbols and no longer split personal info tokens; a password that was accepted before can now be rejected for `PASSWORD_MISSING_SYMBOL` or `PASSWORD_CONTAINS_PERSONAL_INFO`. Names and passwords are compared in NFC, so a name stored with decomposed accents (`e` followed by U+0301) or Thai marks typed in a different order match the same name in the password; a password with the unaccented name is still accepted. Stored passwords are not re-checked.

Where the policy is enforced: `/sign-up/email`, `/change-password`, `/reset-password`, `/email-otp/reset-password`, `/phone-number/reset-password`, `/admin/set-user-password`, `/admin/create-user` (complexity, including `minLength`, but no history) and the server-only `auth.api.setPassword`. Sign-in never runs complexity or history checks.

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
| `PASSWORD_POLICY_UNAVAILABLE` | 503 | Password policy is unavailable, try again later |

`complexity.minLength` rejects with Better Auth's own `PASSWORD_TOO_SHORT` (400), not a code of this plugin. `PASSWORD_POLICY_UNAVAILABLE` is only thrown when `tenantPolicy` fails, see [Per-tenant policy](#per-tenant-policy).

## Server-only endpoints

The plugin has no HTTP routes. These endpoints exist only on `auth.api` so that no request from a browser can unlock an account or flag a user:

| Endpoint | Input | Result |
| --- | --- | --- |
| `auth.api.setPasswordChangeRequired` | `body: { userId, required }` | `{ status: true }` |
| `auth.api.unlockSignIn` | `body: { userId }` | `{ status: true }` |
| `auth.api.getPasswordPolicyStatus` | `query: { userId }` | `{ mustChangePassword, passwordChangedAt, passwordExpiresAt, passwordChangeRequirement, lockedUntil, failedSignInAttempts, policy }` |

An unknown `userId` fails with 404 `USER_NOT_FOUND`. A failing `tenantPolicy` fails with 503 `PASSWORD_POLICY_UNAVAILABLE`.

`unlockSignIn` deletes the user's identifier rows and device rows. It does not revoke device cookies. `lockedUntil` and `failedSignInAttempts` cover the user's identifier rows and the device rows of that user.

`policy` is the effective policy of that user (the platform policy merged with the tenant override), ready to show in a change-password form. `passwordExpiresAt`, `passwordChangeRequirement`, `lockedUntil` and `failedSignInAttempts` follow it too. `minLength` is the larger of Better Auth's `minPasswordLength` and `complexity.minLength`; a section is `null` when that feature is `false`; `expiration` is `null` when passwords do not expire; `duration` is in seconds; `complexity` also reports `caselessLettersSatisfyCase`; `customValidation` tells whether a `validate` function exists. With the default options and no tenant override:

```json
{"minLength":8,"maxLength":128,"complexity":{"requireUppercase":true,"requireLowercase":true,"requireDigit":true,"requireSymbol":false,"rejectPersonalInfo":true,"caselessLettersSatisfyCase":false,"customValidation":false},"history":{"count":5},"expiration":null,"lockout":{"maxAttempts":5,"duration":900}}
```

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

const requirement = getPasswordChangeRequirement(session.user, status.policy.expiration?.maxAge ?? null);
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

Failed attempts are counted on `/sign-in/email`, `/sign-in/username` and `/sign-in/phone-number`, per identifier (`email:<lowercase email>`, `username:<normalized username>`, `phone:<phone number>`) or, for a trusted device, per device. Every sign-in attempt that does not present the correct password counts, including malformed input, unknown accounts and any error response. After `maxAttempts` such attempts the counter is locked for `duration` seconds and further sign-ins on it answer 429 `SIGN_IN_LOCKED` without checking the password. Presenting the correct password always resets the counter that was used, whatever the response is afterwards (success, two-factor, unverified email, banned user, or a response rewritten by another hook); the plugin decides this from the password verification itself, not from the response. Resetting the password and `auth.api.unlockSignIn` also delete the user's rows. Counting is atomic: an attempt is reserved before the password is verified, so concurrent requests cannot verify more than `maxAttempts` passwords per lock window.

### Stored identifiers

The `identifier` column never holds an email, username or phone number. It holds `i1:` followed by 64 hex characters (an HMAC-SHA256 of the identifier) for identifier rows, and `d1:<64 hex>:<32 hex>` (an HMAC of the user id, then the device id) for device rows. The HMAC key is derived from the Better Auth secret with HKDF-SHA256 and a purpose-specific salt and info, so it is not the key that signs cookies. This is pseudonymisation, not anonymisation: whoever holds the secret can test whether a known email or phone number has a row, and low-entropy values such as phone numbers can be brute-forced with it. Keep the secret out of the database backups that hold these rows.

### Device cookie

A locked identifier would otherwise lock the real owner out whenever someone else guesses their email. After a verified password the response sets the cookie `better-auth.password_policy_device` (the name follows `advanced.cookiePrefix`, `__Secure-` on HTTPS and `advanced.cookies.password_policy_device`). It is signed with the Better Auth secret and uses the default cookie attributes (`HttpOnly`, `SameSite=Lax`, `Path=/`, `Max-Age` from `lockout.deviceCookie.maxAge`). The value carries a random device id, an expiry and a binding to the user and to the user's `passwordChangedAt`.

- The cookie is issued whenever the correct password was verified, also on a two-factor redirect and on a 403 for a banned user or an unverified email, and never on a failure, a 429 or a 503. Every verified sign-in rotates it.
- A sign-in that presents a valid cookie of the same user is counted in a counter of its own, not in the identifier counter. One cookie covers the email, username and phone sign-ins of the user.
- An owner whose identifier is locked by an attacker can still sign in from the trusted device. A trusted success resets only the device counter, never the identifier counter, otherwise an attacker would get a new guess quota every time the owner signs in.
- A new device without the cookie during an attack is still locked, like before.
- A device lock does not lock the identifier: the same user without the cookie can still try, and is counted under the identifier.
- The cookie is ignored, and the attempt is counted under the identifier, when the signature is wrong, the expiry has passed, it belongs to another user than the identifier, or the user changed the password after it was issued (any covered password path sets `passwordChangedAt`). Rotating the secret invalidates every cookie.
- A browser holds one cookie. When another user signs in successfully on the same browser, that user owns the cookie and the previous user is untrusted there until the next sign-in.
- Clients that do not keep cookies (bearer-only native apps, server code calling `auth.api.signInEmail` without forwarding the request headers and the `Set-Cookie` of the response) are always untrusted and are counted per identifier.
- There is no server state for the cookie and no revocation of a single cookie. It stops working at `maxAge`, on password change or on secret rotation.
- `lockout: { deviceCookie: false }` never reads or sets it.

### Retention

Rows of identifiers and devices that never succeed would accumulate, so the plugin deletes rows whose last attempt is older than `lockout.retention` (30 days by default) and that are not locked. A row that is still locked is never deleted. The purge runs at most once an hour per plugin instance (not per process), so create the auth instance once instead of per request, or set `advanced.backgroundTasks.handler`. It is triggered by a sign-in request (also a rejected one), in the background when `advanced.backgroundTasks.handler` is set and otherwise before that request continues. A failure is logged and never fails a sign-in. `retention: false` disables it, and then you can clean up yourself:

```sql
delete from sign_in_lockout
where (locked_until is null or locked_until < now())
  and last_attempt_at < now() - interval '30 days';
```

### Behavior to know about

- Counting is keyed by the identifier, not by user, so identifiers that do not belong to any account lock exactly like real ones. Without `tenantPolicy`, the 429 therefore reveals only that this string had too many attempts, which the caller caused. It does not reveal whether an account exists. Without `tenantPolicy`, the plugin looks the user up before the password check only when the request carries a validly signed, unexpired device cookie (also when the counter is locked, because the lookup decides which counter applies), and after the check only when the password was correct, to issue the cookie. A wrong password without such a cookie triggers no lookup by the plugin.
- With `tenantPolicy`, the plugin looks the user up by the identifier (email, normalized username or phone number) before reserving the attempt, and applies the tenant's `maxAttempts` and `duration` (stricter than the platform values only), also for a device counter. A tenant with a lower `maxAttempts` locks a real account sooner than an unknown identifier, so an attacker can observe whether an account exists from the number of attempts before the 429. The lookup runs for every identifier so its own timing does not depend on the account; the latency of your callback is yours to keep uniform. The callback is skipped while the counter being used is locked (the 429 answers first), and the user is looked up from the identifier, never from a header, so as long as your callback does not choose the tenant from headers, a caller cannot pick a looser tenant.
- If `tenantPolicy` fails, the sign-in answers 503 `PASSWORD_POLICY_UNAVAILABLE` before anything is reserved or verified, so the counter does not move.
- A user who can sign in with email, username and phone gets up to `3 * maxAttempts` attempts per lock window from untrusted clients, because the three identifiers are counted separately, plus `maxAttempts` for every trusted device. Locking one identifier does not lock the others.
- Anyone can lock any identifier by failing sign-ins for it. This is inherent to account lockout, but the owner on a trusted device keeps access. Combine with IP rate limiting.
- The correct password with an error that is not about the password (banned user, unverified email, two-factor required) resets the counter and is never counted. Requests that never reach password verification (validation errors, unknown account, account without a password, an unverified phone number when the phoneNumber plugin has `requireVerification`) are counted.
- Rotating the Better Auth secret (or its first entry in `secrets`) changes every stored identifier: counters restart, current locks are released and every device cookie becomes invalid.

## Per-tenant policy

`tenantPolicy` lets one deployment enforce a different policy per tenant (organization, plan, customer). The platform options are the floor; a tenant can only make the policy stricter, never looser.

```ts
passwordPolicy({
  complexity: { minLength: 8 },
  history: { count: 3 },
  lockout: { maxAttempts: 5, duration: 900 },
  tenantPolicy: async ({ user, email }) => {
    const tenant = await findTenant({ userId: user?.id ?? null, email });
    return tenant?.passwordPolicy ?? null;
  },
});
```

Return `null` or `undefined` for no override. Anything else must be an object that passes `validateTenantPasswordPolicyOverride`; every level is strict, so an unknown key (a typo) is invalid and `null` field values are invalid.

| Field | Merge with the platform value | Allowed |
| --- | --- | --- |
| `complexity.requireUppercase`, `requireLowercase`, `requireDigit`, `requireSymbol`, `rejectPersonalInfo` | `true` if either is `true` | boolean |
| `complexity.caselessLettersSatisfyCase` | `true` only if the platform is `true` and the tenant is not `false` (a tenant can switch it off, never on) | boolean |
| `complexity.minLength` | larger | integer 1 to 128 |
| `history.count` | larger | integer 0 to 24 |
| `expiration.maxAge` | smaller of the values that are set | integer 86400 to 315360000 seconds |
| `lockout.maxAttempts` | smaller | integer 1 to 100 |
| `lockout.duration` | larger | integer 1 to 86400 seconds |

Bounds are inclusive and exported as `TENANT_PASSWORD_POLICY_LIMITS`. `complexity.validate`, `lockout.retention` and `lockout.deviceCookie` are platform-only. A feature the platform set to `false` stays off: its override is ignored and the callback is not called for it.

The callback receives a `context` with:

| Field | Value |
| --- | --- |
| `user` | The user as a shallow copy, or `null` when the user does not exist yet. For the session user (change password, gate), fields Better Auth does not return are absent. |
| `email` | The user's email, or the lowercased email from the request body. `null` when unknown. |
| `path` | The endpoint path, or `null` (status, `auth.api.setPassword`, outside an endpoint). |
| `headers` | A copy of the request headers, or `null`. |
| `request` | The `Request`, or `null`. |

| Where | `user` | `email` |
| --- | --- | --- |
| `/sign-up/email`, `/admin/create-user` | `null` | body email, lowercased |
| `/change-password`, `auth.api.setPassword` | session user | user email |
| `/reset-password`, `/email-otp/reset-password`, `/phone-number/reset-password`, `/admin/set-user-password` | owner of the token or target user, `null` if not found | user email, or `null` |
| Sign-in lockout | user found from the identifier, else `null` | user email, else the lowercased body email on `/sign-in/email` |
| Expiry gate | session user | user email |
| Status | user row | user email |

When it is called: only when the answer can matter, and at most once per user per request (the result is cached for the request). It is not called when no `tenantPolicy` is set, when every feature is `false`, for the hash check when complexity is `false` and history does not apply, for the expiry gate when the user is already forced or expired under the platform policy, has no `passwordChangedAt` or passwords never expire, for lockout while the counter being used is locked, and for history pruning when the user has no more rows than the platform keeps. The expiry gate runs on nearly every authenticated request, so cache the tenant lookup. The plugin applies no timeout to the callback.

Failure is closed: if the callback throws, rejects or returns an invalid override, the plugin logs the error and answers 503 `PASSWORD_POLICY_UNAVAILABLE`; it never falls back to the platform policy.

| Where | On failure |
| --- | --- |
| Sign-up, change password, reset password, `/admin/create-user`, `/admin/set-user-password` | 503, the password is not changed and no user is created |
| Sign-in | 503 before anything is reserved or verified |
| Expiry gate | 503 on gated routes (not on the exempt routes, and not when a password change is already forced) |
| Status | 503 |
| History pruning after a password write | Pruning is skipped and every row is kept; `passwordChangedAt`, the forced-change flag and the lockout rows are still updated |

A tenant store outage therefore blocks, for every user including users without a tenant: authenticated requests of users who have a `passwordChangedAt`, every password sign-in while `lockout` is on, and every sign-up, password change and reset while `complexity` or `history` is on. Do not call a gated `auth.api` method from the callback: it runs the gate again and recurses. Do not trust request fields a caller can forge (headers, host) to choose the tenant at sign-up or sign-in; derive it from data you control.

Validate an override before saving it, on the server or in the browser with the same validator:

```ts
import { validateTenantPasswordPolicyOverride } from "@ttar-dev/better-password-policy/client";

const result = validateTenantPasswordPolicyOverride(input);
if (!result.success) {
  return result.issues;
}
await savePolicy(tenantId, result.data);
```

`issues` is a list of `{ path, message }` with a dotted `path` (`""` for the root); the `message` text is not a contract.

Notes:

- The policy follows the user, not the active organization, because sign-in and expiry have no active organization. If a user belongs to several tenants, return the override you want enforced, for example the strictest.
- Raising `history.count` for a tenant takes effect gradually: rows older than the platform window were already pruned. Lowering it prunes to the new value on the next password write.
- `complexity.minLength` from a tenant is checked first and answers `PASSWORD_TOO_SHORT`, like the platform value.

## Plugin order

Put any plugin whose before-hook can reject or short-circuit a sign-in (for example `captcha`) before `passwordPolicy` in the `plugins` array. The lockout reserves an attempt in its before-hook and clears it in its after-hook only when the correct password was verified, so a request rejected by a before-hook that runs after `passwordPolicy` also counts as a failed attempt.

`passwordPolicy` works in any order relative to `twoFactor` and `haveIBeenPwned`.

The after-hook of the lockout sets the device cookie, so keep `nextCookies()` last in the `plugins` array.

## Limitations

- Password writes made by calling `internalAdapter.updatePassword` or `internalAdapter.updateAccount` directly, outside an endpoint, are not recorded in the history and do not update `passwordChangedAt`. Account creation is always recorded.
- Password-setting endpoints added by third-party plugins are not covered by the policy.
- If recording fails after the password was already changed, the error is logged and the request still succeeds; that password can then be reused later.
- `/admin/create-user` is checked before the admin plugin authorizes the request, so an unauthenticated caller can learn the complexity rules (they are not secret), including the rules of the tenant your `tenantPolicy` picks from the email in the body, and can make your callback run. `complexity.minLength` is enforced there; Better Auth's `minPasswordLength` is not.
- With `/email-otp/reset-password`, Better Auth consumes the OTP up front only when it does not match. A valid OTP stays usable after the policy rejects the new password, so the user can retry with a stronger one.
- An admin session impersonating a flagged user is gated like that user, except `/admin/stop-impersonating`, which stays open.
- The server-only `auth.api.setPassword` answers 400 `PASSWORD_ALREADY_SET` for any password when the user already has one, exactly like Better Auth, and applies the policy only when the user has no password yet.
- Clients that do not keep cookies (bearer-only native apps, server code that does not forward headers and `Set-Cookie`) never get a trusted device and are counted per identifier.
- Password writes outside an endpoint do not change `passwordChangedAt`, so they do not invalidate device cookies.
- On Postgres, finding the device rows of a user (`starts_with` on `identifier`) can scan the lockout table sequentially; it happens on password writes, `unlockSignIn`, the status endpoint and user deletion. On Postgres, when the database collation is not C, create `create index on sign_in_lockout (identifier text_pattern_ops);` so these per-user device-row lookups stay indexed.
- A `complexity.minLength` (platform or tenant) above Better Auth's `maxPasswordLength` makes passwords impossible to set.
- The `user` the expiry gate passes to `tenantPolicy` is the session user, so fields with `returned: false` are absent.
