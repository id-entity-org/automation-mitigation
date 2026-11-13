import {mkdir,readFile} from 'node:fs/promises';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const dist=join(root,'dist');
await mkdir(dist,{recursive:true});
for(const suffix of ['','-high','-high-mem','-high-cpu']){
  const result=await build({
    entryPoints:[join(root,'lib.mjs')],
    bundle:false,
    minify:true,
    outfile:join(dist,`lib${suffix}-min.mjs`),
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
              const contents=(await readFile(args.path,'utf8')).replace(
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
    process.exit(1);
  }
}
