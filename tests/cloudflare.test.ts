import { describe, expect, test } from "bun:test";
import { createD1RateLimiter, type D1Database } from "../src/cloudflare.js";

type D1Value = string | number | boolean | null | ArrayBuffer | ArrayBufferView;
type PreparedStatement = {
  bind(...values: D1Value[]): PreparedStatement;
  first<Row>(): Promise<Row | null>;
  all<Row>(): Promise<{ results?: Row[] }>;
  run(): Promise<{ success?: boolean }>;
};
describe("D1 auth rate limiter", () => {
  test("hashes identifier values and separates email from username keys", async () => {
    const bindings: unknown[][] = [];
    const db: D1Database = {
      prepare() {
        const statement: PreparedStatement = {
          bind(...values) {
            bindings.push(values);
            return statement;
          },
          async first<Row>() { return null as Row | null; },
          async all<Row>() { return { results: [] as Row[] }; },
          async run() { return {}; },
        };
        return statement;
      },
      async batch<Row>(statements: PreparedStatement[]) {
        return statements.map(() => ({ results: [{ count: 1, window_start_ms: 0 } as Row] }));
      },
    };
    const limiter = createD1RateLimiter(db, {
      identifier: { limit: 5, windowSeconds: 60 },
      ip: { limit: 10, windowSeconds: 60 },
      now: () => 10_000,
    });

    await limiter.check({ action: "login", identifier: { type: "email", value: "same@example.test" }, ip: "192.0.2.1" });
    await limiter.check({ action: "login", identifier: { type: "username", value: "same@example.test" }, ip: "192.0.2.1" });

    expect(bindings[0]?.[0]).toMatch(/^[a-f0-9]{64}$/);
    expect(bindings[0]?.[0]).not.toBe(bindings[2]?.[0]);
    expect(bindings[0]).not.toContain("same@example.test");
    expect(bindings[2]).not.toContain("same@example.test");
  });
});
