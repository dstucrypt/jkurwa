import { describe, it, expect } from "vitest";
import { loadAsset, kupynaBox } from "./utils.js";

describe("CZO CAdES-T Dstu7564 (Kupyna)", () => {
  const p7s = loadAsset("test-t-kupyna.p7s");

  it("unwraps and verifies Kupyna CAdES-T signature", async () => {
    const box = kupynaBox();
    const { content, pipe } = await box.unwrap(p7s);
    expect(content.toString()).toBe("Test\r\n");
    expect(pipe[0].signed).toBe(true);
    expect(pipe[0].cert.subject.commonName).toBe("ТЕСТ Тестовий Тест Тестович");
  });

  it("unwraps with CA verification using test root", async () => {
    const box = kupynaBox();
    box.loadCAs(loadAsset("CZO-CA-LIST.p7s"));
    const { content, pipe } = await box.unwrap(p7s);
    expect(content.toString()).toBe("Test\r\n");
    expect(pipe[0].signed).toBe(true);
    expect(pipe[0].cert.verified).toBe(true);
  });
});
