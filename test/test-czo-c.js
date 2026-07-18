import { describe, it } from "vitest";
import { expectCzoVerified } from "./utils.js";

// CZO test example: CAdES-C (with reference to complete data for
// verification), DSTU 4145 / GOST 34.311. Source: https://czo.gov.ua/testexamples
describe("CZO CAdES-C", () => {
  it("unwraps with CA verification", () => expectCzoVerified("test-c-gost.p7s"));
});
