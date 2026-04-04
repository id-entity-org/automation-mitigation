import {assertEquals} from "asserts";

for(const test of [
  {name:'Test1 default',suffix:'',expected:'be04c35e9d55d41b58f1578c2b60f487471e480b506343eb19873dda4438f277'},
  {name:'Test1 high cpu',suffix:'-high-cpu',expected:'4f29dbf5f60c027c0e22696d8a109c89cb5d433eb655d96e45f7df5e7d00ef1f'},
  {name:'Test1 high memory',suffix:'-high-mem',expected:'48d5b0ba240fcf211dede5f950108bcf081e453c48e1d8bb20b413290c163b6f'},
  {name:'Test1 high cpu and memory',suffix:'-high',expected:'f8545c0973957c0b0ae86a6470d404a4359b753a3c9127c23b8fa1a6ba1abece'}
]){
  Deno.test({
    name:test.name,
    fn:async()=>{
      const nonce=new Uint8Array(16);
      nonce.setFromHex("0b206ed758abdcb0d43c9bb3e7808495");
      const {default:pow}=await import(`./lib${test.suffix}-min.mjs`);
      const abortController=new AbortController();
      const proof=await pow(nonce,abortController.signal);
      const hashBuffer=await crypto.subtle.digest('SHA-256',proof);
      const hash=new Uint8Array(hashBuffer).toHex();
      assertEquals(hash,test.expected);
    },
    sanitizeResources:false,
    sanitizeOps:false,
  });
}

for(const test of [
  {name:'Test2 default',suffix:'',expected:'3b44d3f3762e1d6a757bb65b110c1f358f2a30c63636c780370e4379e4ea273a'},
  {name:'Test2 high cpu',suffix:'-high-cpu',expected:'0918856e32785ca82551af68fd8b4417471742c094964ede4d706a314ce46dd8'},
  {name:'Test2 high memory',suffix:'-high-mem',expected:'cfd2f0644f82a4c8fa47fc2102a73d5c7b84fee637d88c2436f359b1a700df80'},
  {name:'Test2 high cpu and memory',suffix:'-high',expected:'0654929e517a42bf0460cae5ba119e14166e45358dbe4ae72bb43b74c177d00e'}
]){
  Deno.test({
    name:test.name,
    fn:async()=>{
      const nonce=new Uint8Array(16);
      nonce.setFromHex("8b7df143d91c716ecfa5fc1730022f6b");
      const {default:pow}=await import(`./lib${test.suffix}-min.mjs`);
      const abortController=new AbortController();
      const proof=await pow(nonce,abortController.signal);
      const hashBuffer=await crypto.subtle.digest('SHA-256',proof);
      const hash=new Uint8Array(hashBuffer).toHex();
      assertEquals(hash,test.expected);
    },
    sanitizeResources:false,
    sanitizeOps:false,
  });
}
