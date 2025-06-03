import { defineConfig } from "vite";

export default defineConfig({
  test: {
    include: "test/test*{j,t}s",
    setupFiles: "test/setup.js"
  }
});
