import {execFileSync} from 'node:child_process';
import {copyFile,mkdir,readFile,writeFile} from 'node:fs/promises';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';
import {brotliCompress} from 'node:zlib';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const dist=join(root,'dist');
const brotli=promisify(brotliCompress);
const builds=[
  {features:null,out:'lib.wasm'},
  {features:'high-cpu',out:'lib-high-cpu.wasm'},
  {features:'high-memory',out:'lib-high-mem.wasm'},
  {features:'high-memory,high-cpu',out:'lib-high.wasm'},
];
const outputs=[
  'lib.mjs',
  'lib-min.mjs',
  'lib-high-cpu-min.mjs',
  'lib-high-mem-min.mjs',
  'lib-high-min.mjs',
  ...builds.map(({out})=>out),
];

await mkdir(dist,{recursive:true});
for(const {features,out} of builds){
  const args=['build','--release','--no-default-features'];
  if(features) args.push('--features',features);
  execFileSync('cargo',args,{cwd:root,stdio:'inherit'});
  await copyFile(
    join(root,'..','target','wasm32-unknown-unknown','release','automation_mitigation_wasm.wasm'),
    join(dist,out)
  );
}

await copyFile(join(root,'lib.mjs'),join(dist,'lib.mjs'));
execFileSync(process.execPath,[join(dirname(fileURLToPath(import.meta.url)),'minimize.mjs')],{stdio:'inherit'});

for(const file of outputs){
  await writeFile(join(dist,`${file}.br`),await brotli(await readFile(join(dist,file))));
}
