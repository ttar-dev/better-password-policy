import { describe, it, expect, afterEach, vi } from "vitest";
import {
  createAuthRegistry,
  captureApiError,
  expectTooManyRequests,
  expectUnauthorized,
  DEFAULT_EMAIL,
  DEFAULT_PASSWORD,
  WRONG_PASSWORD,
} from "../harness/create-test-auth.ts";
import type { TestAuth } from "../harness/create-test-auth.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  await registry.closeAll();
});

const START = new Date("2026-06-01T00:00:00.000Z");
const DAY = 86_400_000;
const HOUR = 3_600_000;
const PURGE_MESSAGE = "password-policy: failed to purge stale sign-in lockout rows";
const policy = { lockout: { maxAttempts: 3 } };

const freezeClock = () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(START);
};

const advanceClock = (milliseconds: number) => {
  vi.setSystemTime(new Date(Date.now() + milliseconds));
};

interface SeedInput {
  name: string;
  lastAttemptAgoMs: number;
  lockedUntilFromNowMs: number | null;
}

const seed = (t: TestAuth, input: SeedInput) =>
  t.adapter.create({
    model: "signInLockout",
    data: {
      identifier: `seed:${input.name}`,
      failedAttempts: 3,
      lockedUntil:
        input.lockedUntilFromNowMs === null ? null : new Date(Date.now() + input.lockedUntilFromNowMs),
      lastAttemptAt: new Date(Date.now() - input.lastAttemptAgoMs),
    },
  });

const seededNames = async (t: TestAuth): Promise<string[]> =>
  (await t.lockoutRows())
    .map((row) => row.identifier)
    .filter((identifier) => identifier.startsWith("seed:"))
    .map((identifier) => identifier.slice("seed:".length))
    .sort();

const seedMixedRows = async (t: TestAuth) => {
  await seed(t, { name: "stale-unlocked", lastAttemptAgoMs: 31 * DAY, lockedUntilFromNowMs: null });
  await seed(t, { name: "stale-lock-expired", lastAttemptAgoMs: 31 * DAY, lockedUntilFromNowMs: -DAY });
  await seed(t, { name: "stale-lock-active", lastAttemptAgoMs: 31 * DAY, lockedUntilFromNowMs: HOUR });
  await seed(t, { name: "fresh-unlocked", lastAttemptAgoMs: DAY, lockedUntilFromNowMs: null });
  await seed(t, { name: "fresh-lock-expired", lastAttemptAgoMs: DAY, lockedUntilFromNowMs: -HOUR });
  await seed(t, { name: "fresh-lock-active", lastAttemptAgoMs: DAY, lockedUntilFromNowMs: HOUR });
};

const KEPT_BY_DEFAULT = ["fresh-lock-active", "fresh-lock-expired", "fresh-unlocked", "stale-lock-active"];

const wrongEmail = (t: TestAuth) =>
  expectUnauthorized(
    () => t.auth.api.signInEmail({ body: { email: DEFAULT_EMAIL, password: WRONG_PASSWORD } }),
    "INVALID_EMAIL_OR_PASSWORD",
  );

const correctEmail = (t: TestAuth) =>
  t.auth.api.signInEmail({ body: { email: DEFAULT_EMAIL, password: DEFAULT_PASSWORD } });

const ownRows = async (t: TestAuth) =>
  (await t.lockoutRows()).filter((row) => !row.identifier.startsWith("seed:"));

describe("lockout retention purge", () => {
  it("deletes stale unlocked rows and stale rows with an expired lock on the first sign-in but keeps stale rows still locked and fresh rows", async () => {
    freezeClock();
    const t = await open({ policy });
    await t.signUp();
    await seedMixedRows(t);
    await wrongEmail(t);
    expect(await seededNames(t)).toEqual(KEPT_BY_DEFAULT);
  });

  it("purges when the triggering sign-in succeeds", async () => {
    freezeClock();
    const t = await open({ policy });
    await t.signUp();
    await seedMixedRows(t);
    const result = await correctEmail(t);
    expect(result.user.email).toBe(DEFAULT_EMAIL);
    expect(await seededNames(t)).toEqual(KEPT_BY_DEFAULT);
  });

  it("keeps a row whose last attempt is just inside the retention window", async () => {
    freezeClock();
    const t = await open({ policy });
    await t.signUp();
    await seed(t, { name: "inside", lastAttemptAgoMs: 30 * DAY - 60_000, lockedUntilFromNowMs: null });
    await seed(t, { name: "outside", lastAttemptAgoMs: 30 * DAY + 60_000, lockedUntilFromNowMs: null });
    await wrongEmail(t);
    expect(await seededNames(t)).toEqual(["inside"]);
  });

  it("also purges on a request answered with 429", async () => {
    freezeClock();
    const t = await open({ policy: { lockout: { maxAttempts: 3, duration: 86_400 } } });
    await t.signUp();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await wrongEmail(t);
    }
    advanceClock(2 * HOUR);
    await seedMixedRows(t);
    const error = await captureApiError(() => correctEmail(t));
    expect(error.statusCode).toBe(429);
    expect(await seededNames(t)).toEqual(KEPT_BY_DEFAULT);
  });

  it("also purges on a sign-in request without an identifier", async () => {
    freezeClock();
    const t = await open({ policy });
    await t.signUp();
    await seedMixedRows(t);
    const error = await captureApiError(() =>
      t.auth.api.signInEmail({ body: { password: DEFAULT_PASSWORD } as never }),
    );
    expect(error.statusCode).toBe(400);
    expect(await seededNames(t)).toEqual(KEPT_BY_DEFAULT);
  });

  it("purges at most once an hour per instance", async () => {
    freezeClock();
    const t = await open({ policy });
    await t.signUp();
    await wrongEmail(t);

    await seed(t, { name: "late-one", lastAttemptAgoMs: 31 * DAY, lockedUntilFromNowMs: null });
    await wrongEmail(t);
    expect(await seededNames(t)).toEqual(["late-one"]);

    advanceClock(HOUR - 1000);
    await correctEmail(t);
    expect(await seededNames(t)).toEqual(["late-one"]);

    advanceClock(2000);
    await wrongEmail(t);
    expect(await seededNames(t)).toEqual([]);
  });

  it("applies a custom retention", async () => {
    freezeClock();
    const t = await open({ policy: { lockout: { maxAttempts: 3, retention: 2 * 86_400 } } });
    await t.signUp();
    await seed(t, { name: "three-days", lastAttemptAgoMs: 3 * DAY, lockedUntilFromNowMs: null });
    await seed(t, { name: "one-day", lastAttemptAgoMs: DAY, lockedUntilFromNowMs: null });
    await wrongEmail(t);
    expect(await seededNames(t)).toEqual(["one-day"]);
  });

  it("keeps rows older than a custom retention that is longer than the default", async () => {
    freezeClock();
    const t = await open({ policy: { lockout: { maxAttempts: 3, retention: 90 * 86_400 } } });
    await t.signUp();
    await seed(t, { name: "sixty-days", lastAttemptAgoMs: 60 * DAY, lockedUntilFromNowMs: null });
    await seed(t, { name: "hundred-days", lastAttemptAgoMs: 100 * DAY, lockedUntilFromNowMs: null });
    await wrongEmail(t);
    expect(await seededNames(t)).toEqual(["sixty-days"]);
  });

  it("never purges when retention is false", async () => {
    freezeClock();
    const t = await open({ policy: { lockout: { maxAttempts: 3, retention: false } } });
    await t.signUp();
    await seedMixedRows(t);
    await wrongEmail(t);
    advanceClock(2 * HOUR);
    await wrongEmail(t);
    expect(await seededNames(t)).toHaveLength(6);
  });

  it("never purges when lockout is switched off", async () => {
    freezeClock();
    const t = await open({ policy: { lockout: false } });
    await t.signUp();
    await seedMixedRows(t);
    await wrongEmail(t);
    const result = await correctEmail(t);
    expect(result.user.email).toBe(DEFAULT_EMAIL);
    expect(await seededNames(t)).toHaveLength(6);
  });
});

const failPurgeDeletes = (t: TestAuth, message = "purge storage down") => {
  const original = t.adapter.deleteMany.bind(t.adapter);
  return vi.spyOn(t.adapter, "deleteMany").mockImplementation(async (input) => {
    if (input.where?.some((clause) => clause.field === "lastAttemptAt")) {
      throw new Error(message);
    }
    return original(input);
  });
};

const silenceErrorLog = (t: TestAuth) =>
  vi.spyOn(t.context.logger, "error").mockImplementation(() => undefined);

const loggedPurgeFailure = (logged: ReturnType<typeof silenceErrorLog>) =>
  logged.mock.calls.some((call) => String(call[0]).includes(PURGE_MESSAGE));

describe("lockout retention purge failures", () => {
  it("still answers a wrong password with 401, counts it and logs the purge failure", async () => {
    const t = await open({ policy });
    await t.signUp();
    const deletes = failPurgeDeletes(t);
    const logged = silenceErrorLog(t);
    await wrongEmail(t);
    expect(deletes).toHaveBeenCalled();
    expect((await ownRows(t))[0]?.failedAttempts).toBe(1);
    expect(loggedPurgeFailure(logged)).toBe(true);
  });

  it("still signs in with the correct password when the purge fails", async () => {
    const t = await open({ policy });
    await t.signUp();
    failPurgeDeletes(t);
    const logged = silenceErrorLog(t);
    const result = await correctEmail(t);
    expect(result.user.email).toBe(DEFAULT_EMAIL);
    expect(loggedPurgeFailure(logged)).toBe(true);
  });

  it("does not retry a failed purge before the interval has passed", async () => {
    freezeClock();
    const t = await open({ policy });
    await t.signUp();
    const deletes = failPurgeDeletes(t);
    silenceErrorLog(t);
    await wrongEmail(t);
    const attemptsAfterFirst = deletes.mock.calls.filter((call) =>
      call[0].where?.some((clause) => clause.field === "lastAttemptAt"),
    ).length;
    await wrongEmail(t);
    const attemptsAfterSecond = deletes.mock.calls.filter((call) =>
      call[0].where?.some((clause) => clause.field === "lastAttemptAt"),
    ).length;
    expect(attemptsAfterFirst).toBeGreaterThan(0);
    expect(attemptsAfterSecond).toBe(attemptsAfterFirst);
  });
});

const collectLoggedStrings = (value: unknown, depth = 0): string[] => {
  if (value === null || value === undefined || depth > 5) {
    return [];
  }
  if (typeof value !== "object") {
    return [String(value)];
  }
  const collected = [String(value)];
  try {
    collected.push(JSON.stringify(value));
  } catch {
    collected.push("");
  }
  if (value instanceof Error) {
    collected.push(value.name, value.message, value.stack ?? "");
    collected.push(...collectLoggedStrings(value.cause, depth + 1));
  }
  for (const nested of Object.values(value)) {
    collected.push(...collectLoggedStrings(nested, depth + 1));
  }
  return collected;
};

const serializeLoggedCalls = (calls: unknown[][]): string =>
  calls.flatMap((args) => args.flatMap((arg) => collectLoggedStrings(arg))).join("\n");

describe("lockout retention purge log hygiene", () => {
  it("logs the constant purge message and no identifier when the purge error message contains an email", async () => {
    const t = await open({ policy });
    await t.signUp();
    failPurgeDeletes(t, `Failed query: delete from sign_in_lockout params: ${DEFAULT_EMAIL}`);
    const logged = silenceErrorLog(t);
    await wrongEmail(t);
    const purgeCalls = logged.mock.calls.filter((call) => String(call[0]).includes(PURGE_MESSAGE));
    expect(purgeCalls.length).toBeGreaterThan(0);
    expect(purgeCalls.every((call) => call[0] === PURGE_MESSAGE)).toBe(true);
    expect(serializeLoggedCalls(logged.mock.calls)).not.toContain(DEFAULT_EMAIL);
  });
});

describe("lockout retention with a lock longer than the retention", () => {
  const longLockPolicy = { lockout: { maxAttempts: 2, duration: 2_678_400 } };

  it("keeps a still-locked row whose last attempt is older than the retention and keeps answering 429", async () => {
    freezeClock();
    const t = await open({ policy: longLockPolicy });
    await t.signUp();
    await wrongEmail(t);
    await wrongEmail(t);
    const [locked] = await ownRows(t);
    expect(locked?.lockedUntil).toBeInstanceOf(Date);
    await t.adapter.update({
      model: "signInLockout",
      where: [{ field: "id", value: locked!.id }],
      update: { lastAttemptAt: new Date(Date.now() - 31 * DAY) },
    });
    advanceClock(2 * HOUR);
    await seed(t, { name: "stale-unlocked", lastAttemptAgoMs: 31 * DAY, lockedUntilFromNowMs: null });

    await expectTooManyRequests(() => correctEmail(t), "SIGN_IN_LOCKED");

    expect(await seededNames(t)).toEqual([]);
    const survivors = await ownRows(t);
    expect(survivors).toHaveLength(1);
    expect(survivors[0]?.id).toBe(locked!.id);
    expect(survivors[0]?.lockedUntil!.getTime()).toBeGreaterThan(Date.now());
    await expectTooManyRequests(() => correctEmail(t), "SIGN_IN_LOCKED");
  });
});

describe("lockout retention purge in the background", () => {
  const collectTasks = () => {
    const tasks: Promise<unknown>[] = [];
    return { tasks, handler: (promise: Promise<unknown>) => void tasks.push(promise) };
  };

  it("hands the purge promise to the background handler, which deletes the stale rows once settled", async () => {
    freezeClock();
    const background = collectTasks();
    const t = await open({ policy, backgroundTasks: background.handler });
    await t.signUp();
    await seedMixedRows(t);
    background.tasks.length = 0;
    await wrongEmail(t);
    expect(background.tasks).toHaveLength(1);
    expect(background.tasks[0]).toBeInstanceOf(Promise);
    await expect(background.tasks[0]).resolves.toBeUndefined();
    expect(await seededNames(t)).toEqual(KEPT_BY_DEFAULT);
  });

  it("hands over a purge promise that resolves even when the purge fails", async () => {
    const background = collectTasks();
    const t = await open({ policy, backgroundTasks: background.handler });
    await t.signUp();
    failPurgeDeletes(t);
    const logged = silenceErrorLog(t);
    background.tasks.length = 0;
    await wrongEmail(t);
    expect(background.tasks).toHaveLength(1);
    await expect(background.tasks[0]).resolves.toBeUndefined();
    expect(loggedPurgeFailure(logged)).toBe(true);
  });

  it("hands nothing over for a second sign-in inside the throttle interval", async () => {
    freezeClock();
    const background = collectTasks();
    const t = await open({ policy, backgroundTasks: background.handler });
    await t.signUp();
    await wrongEmail(t);
    background.tasks.length = 0;
    await wrongEmail(t);
    expect(background.tasks).toHaveLength(0);
  });

  it("hands nothing over when retention is false or lockout is off", async () => {
    const noRetention = collectTasks();
    const withoutRetention = await open({
      policy: { lockout: { maxAttempts: 3, retention: false } },
      backgroundTasks: noRetention.handler,
    });
    await withoutRetention.signUp();
    noRetention.tasks.length = 0;
    await wrongEmail(withoutRetention);

    const noLockout = collectTasks();
    const withoutLockout = await open({ policy: { lockout: false }, backgroundTasks: noLockout.handler });
    await withoutLockout.signUp();
    noLockout.tasks.length = 0;
    await wrongEmail(withoutLockout);

    expect(noRetention.tasks).toHaveLength(0);
    expect(noLockout.tasks).toHaveLength(0);
  });
});
