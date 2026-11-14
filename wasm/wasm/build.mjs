import * as esbuild from "npm:esbuild@0.25.0";

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
