import { describe, it, expect } from "vitest";
import {
  getPasswordChangeRequirement,
  getPasswordExpiresAt,
  parsePasswordChangedAt,
} from "../../src/requirement.ts";

const now = new Date("2026-01-01T12:00:00.000Z");
const secondsBefore = (seconds: number) => new Date(now.getTime() - seconds * 1000);

describe("getPasswordChangeRequirement", () => {
  it("returns forced when mustChangePassword is true", () => {
    expect(
      getPasswordChangeRequirement({ mustChangePassword: true, passwordChangedAt: now }, 60, now),
    ).toBe("forced");
  });

  it("returns forced even when no expiration is configured", () => {
    expect(getPasswordChangeRequirement({ mustChangePassword: true }, null, now)).toBe("forced");
  });

  it("lets forced win over expired", () => {
    expect(
      getPasswordChangeRequirement(
        { mustChangePassword: true, passwordChangedAt: secondsBefore(3600) },
        60,
        now,
      ),
    ).toBe("forced");
  });

  it("returns null one second before the password age reaches maxAge", () => {
    expect(
      getPasswordChangeRequirement({ passwordChangedAt: secondsBefore(59) }, 60, now),
    ).toBeNull();
  });

  it("returns expired exactly at the maxAge boundary", () => {
    expect(
      getPasswordChangeRequirement({ passwordChangedAt: secondsBefore(60) }, 60, now),
    ).toBe("expired");
  });

  it("returns expired past the maxAge boundary", () => {
    expect(
      getPasswordChangeRequirement({ passwordChangedAt: secondsBefore(61) }, 60, now),
    ).toBe("expired");
  });

  it("returns null when passwordChangedAt is null", () => {
    expect(
      getPasswordChangeRequirement({ mustChangePassword: false, passwordChangedAt: null }, 60, now),
    ).toBeNull();
  });

  it("returns null when passwordChangedAt is missing", () => {
    expect(getPasswordChangeRequirement({}, 60, now)).toBeNull();
  });

  it("returns null when maxAge is null or undefined", () => {
    const user = { passwordChangedAt: secondsBefore(100000) };
    expect(getPasswordChangeRequirement(user, null, now)).toBeNull();
    expect(getPasswordChangeRequirement(user, undefined, now)).toBeNull();
  });

  it("returns null when mustChangePassword is false or null and nothing expired", () => {
    expect(
      getPasswordChangeRequirement({ mustChangePassword: false, passwordChangedAt: now }, 60, now),
    ).toBeNull();
    expect(
      getPasswordChangeRequirement({ mustChangePassword: null, passwordChangedAt: now }, 60, now),
    ).toBeNull();
  });

  it("accepts ISO strings for passwordChangedAt", () => {
    expect(
      getPasswordChangeRequirement(
        { passwordChangedAt: secondsBefore(60).toISOString() },
        60,
        now,
      ),
    ).toBe("expired");
    expect(
      getPasswordChangeRequirement(
        { passwordChangedAt: secondsBefore(59).toISOString() },
        60,
        now,
      ),
    ).toBeNull();
  });

  it("defaults now to the current time", () => {
    expect(
      getPasswordChangeRequirement({ passwordChangedAt: new Date(Date.now() - 7200_000) }, 3600),
    ).toBe("expired");
    expect(getPasswordChangeRequirement({ passwordChangedAt: new Date() }, 3600)).toBeNull();
  });
});

describe("getPasswordExpiresAt", () => {
  it("adds maxAge seconds to passwordChangedAt", () => {
    expect(getPasswordExpiresAt(now, 3600)).toEqual(new Date("2026-01-01T13:00:00.000Z"));
  });

  it("accepts an ISO string", () => {
    expect(getPasswordExpiresAt(now.toISOString(), 60)).toEqual(
      new Date("2026-01-01T12:01:00.000Z"),
    );
  });

  it("returns null when passwordChangedAt is null or undefined", () => {
    expect(getPasswordExpiresAt(null, 60)).toBeNull();
    expect(getPasswordExpiresAt(undefined, 60)).toBeNull();
  });

  it("returns null when maxAge is null or undefined", () => {
    expect(getPasswordExpiresAt(now, null)).toBeNull();
    expect(getPasswordExpiresAt(now, undefined)).toBeNull();
  });
});

describe("parsePasswordChangedAt", () => {
  it("returns the same instance for a valid Date", () => {
    expect(parsePasswordChangedAt(now)).toBe(now);
  });

  it("returns null for an invalid Date", () => {
    expect(parsePasswordChangedAt(new Date(Number.NaN))).toBeNull();
  });

  it("parses an ISO string", () => {
    expect(parsePasswordChangedAt(now.toISOString())).toEqual(now);
  });

  it("returns null for an unparsable string and for the empty string", () => {
    expect(parsePasswordChangedAt("not a date")).toBeNull();
    expect(parsePasswordChangedAt("")).toBeNull();
  });

  it("reads a number as milliseconds since the epoch", () => {
    expect(parsePasswordChangedAt(now.getTime())).toEqual(now);
  });

  it("returns null for NaN and Infinity", () => {
    expect(parsePasswordChangedAt(Number.NaN)).toBeNull();
    expect(parsePasswordChangedAt(Number.POSITIVE_INFINITY)).toBeNull();
    expect(parsePasswordChangedAt(Number.NEGATIVE_INFINITY)).toBeNull();
  });

  it("returns null for null, undefined, booleans and objects", () => {
    expect(parsePasswordChangedAt(null)).toBeNull();
    expect(parsePasswordChangedAt(undefined)).toBeNull();
    expect(parsePasswordChangedAt(true)).toBeNull();
    expect(parsePasswordChangedAt(false)).toBeNull();
    expect(parsePasswordChangedAt({})).toBeNull();
  });
});
