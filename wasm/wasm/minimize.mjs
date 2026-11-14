import * as esbuild from "https://deno.land/x/esbuild@v0.25.0/mod.js";

await esbuild.initialize({
  worker: false,
});

const result = await esbuild.build({
  entryPoints: ["lib.mjs"],
  bundle: false,
  minify: true,
  outfile: "lib-min.mjs",
  format: "esm",
  platform: "browser",
  target: "esnext",
});

if (result.errors.length > 0) {
  console.error("Build failed with errors:", result.errors);
  Deno.exit(1);
}

console.log("Build successful: lib-min.mjs generated.");
esbuild.stop();
