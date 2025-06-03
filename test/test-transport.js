/* eslint-env mocha */
import assert from "assert";
import fs from "fs";
import * as jk from "../lib";

import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

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
