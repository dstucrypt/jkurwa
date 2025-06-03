import { vi } from "vitest";

const NOT_RANDOM_32 = Buffer.from("12345678901234567890123456789012");
function rng() {
  return NOT_RANDOM_32;
}
vi.mock("node:crypto", () => ({ default: { rng } }));
