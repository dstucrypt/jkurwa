import { describe, it } from "vitest";
import { expectCzoVerified } from "./utils.js";

// CZO test example: CAdES-X Long (Full) - long term with the complete CA/CSP
// data for verification, DSTU 4145 / GOST 34.311.
// Source: https://czo.gov.ua/testexamples
describe("CZO CAdES-X Long Full", () => {
  it("unwraps with CA verification", () => expectCzoVerified("test-xf-gost.p7s"));
});
