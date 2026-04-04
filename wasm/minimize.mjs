import {build,stop} from 'https://deno.land/x/esbuild/mod.js';
for(const suffix of ['','-high','-high-mem','-high-cpu']){
  const result=await build({
    entryPoints:[`lib.mjs`],
    bundle:false,
    minify:true,
    outfile:`lib${suffix}-min.mjs`,
    format:"esm",
    platform:"browser",
    target:"esnext",
    plugins:[
      {
        name:'replace-wasm-path',
        setup(build){
          build.onLoad(
            {filter:/lib.mjs$/},
            async(args)=>{
              const contents=(await Deno.readTextFile(args.path)).replace(
                /const url=new URL\('lib-high.wasm',import.meta.url\);/,
                `const url=new URL('lib${suffix}.wasm',import.meta.url);`
              );
              return {contents};
            }
          );
        }
      }
    ]
  });
  if(result.errors.length>0){
    console.error(result.errors);
    Deno.exit(1);
  }
}
stop();
