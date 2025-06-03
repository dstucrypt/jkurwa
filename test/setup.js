import { jest } from "@jest/globals";

const NOT_RANDOM_32 = Buffer.from("12345678901234567890123456789012");
function rng() {
  return NOT_RANDOM_32;
}
jest.setMock("crypto", { rng });
jest.unstable_mockModule("node:crypto", () => ({ default: { rng } }));
