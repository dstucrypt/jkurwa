/* eslint-env mocha */
import assert from "assert";
import fs from "fs";
import * as jk from "../lib";

describe("Transport", () => {
  it("should serialize data with headers", () => {
    const encoded = jk.transport.encode(
      [{ type: "CLEAR", contents: Buffer.from("123") }],
      { filename: "clear_file.txt" }
    );
    assert.deepEqual(
      encoded,
      fs.readFileSync(`${__dirname}/data/clear_message.transport`)
    );
  });
});
