/* eslint-env mocha */
import * as jk from "../lib";
import { assertEqualSaved } from "./utils.js";

describe("Transport", () => {
  it("should serialize data with headers", () => {
    const encoded = jk.transport.encode(
      [{ type: "CLEAR", contents: Buffer.from("123") }],
      { filename: "clear_file.txt" }
    );
    assertEqualSaved(encoded, "clear_message.transport");
  });
});
