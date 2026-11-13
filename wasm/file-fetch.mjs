import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';

const nativeFetch=globalThis.fetch;
globalThis.fetch=(input,init)=>{
  const url=input instanceof URL?input:typeof input==='string'&&URL.canParse(input)?new URL(input):null;
  if(url?.protocol==='file:'){
    const path=fileURLToPath(url);
    return readFile(path).then(body=>new Response(body,{
      headers:{'content-type':path.endsWith('.wasm')?'application/wasm':'application/octet-stream'},
    }));
  }
  return nativeFetch(input,init);
};
