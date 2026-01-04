// preload
const url=new URL('lib.wasm',import.meta.url);
await(await fetch(url)).arrayBuffer();
let wasm;
const{instance}=await WebAssembly.instantiateStreaming(fetch(url,{cache:'force-cache'}),{js:{
  println:(ptr,len)=>console.log(new TextDecoder().decode(new Uint8Array(wasm.memory.buffer,ptr,len))),
  eprintln:(ptr,len)=>console.error(new TextDecoder().decode(new Uint8Array(wasm.memory.buffer,ptr,len))),
}});
wasm=instance.exports;
const STEP_COUNT=10;
const BLOCK_SIZE=256;
const CHAIN_BLOCK_COUNT=524_288;
/** @typedef {number} ChainPointer */
/** @typedef {number} HashChainPointer */
/** @typedef {number} StatePointer */
/** @typedef {number} BlockIndexPointer */
/** @typedef {{i:number,chain_index:number}} BlockIndex */
/** @typedef {Uint8Array} Block */
/** @typedef {number} BlockPointer */
/** @typedef {number} BlockArrayPointer */
/**
 * Generates a chain of blocks.
 * @param {number} i (chain index: 0 or 1)
 * @param {Uint8Array} nonce (length 16)
 * @return {ChainPointer} a pointer to the computed chain of blocks.
 */
const generateChain=(i,nonce)=>{
  const noncePtr=wasm.alloc_nonce();
  new Uint8Array(wasm.memory.buffer,noncePtr,16).set(nonce);
  const chainPtr=wasm.generate_chain(i,noncePtr);
  wasm.free_nonce(noncePtr, 16);
  return chainPtr;
};
/**
 * Releases the memory of the chain of blocks.
 * @param {ChainPointer} chainPtr
 */
const freeChain=chainPtr=>{
  wasm.free_chain(chainPtr);
};
/**
 * Computes the list of hashes for a chain of blocks.
 * @param {ChainPointer} chainPtr
 * @return {HashChainPointer} a pointer to the computed hashes (same length as the chain).
 */
const hashChain=chainPtr=>{
  return wasm.hash_chain(chainPtr);
};
/**
 * Creates the state (merkle tree) from the combination of the two hash chains.
 * It also releases the memory of the two hash chains.
 * @param {HashChainPointer} chain1Ptr
 * @param {HashChainPointer} chain2Ptr
 * @return {StatePointer} a pointer to the computed state.
 */
const buildState=(chain1Ptr, chain2Ptr)=>{
  return wasm.build_state(chain1Ptr,chain2Ptr);
};
/**
 * Selects the proof indices from the state (merkle root).
 * @param {StatePointer} statePtr
 * @return {{indices_pointer:BlockIndexPointer,chain1:BlockIndex[],chain2:BlockIndex[]}}
 */
const selectIndices=statePtr=>{
  const indicesPtr=wasm.select_indices(statePtr);
  const indices=new Uint32Array(wasm.memory.buffer,indicesPtr,STEP_COUNT);
  const chainIndices=[[],[]];
  indices.forEach((index,i)=>{
    const parentIndex=index-1;
    chainIndices[Math.trunc(parentIndex/CHAIN_BLOCK_COUNT)].push({i,chain_index:parentIndex%CHAIN_BLOCK_COUNT})
  });
  const [chain1,chain2]=chainIndices;
  return {indices_pointer:indicesPtr,chain1,chain2};
};
/**
 * Gets the blocks from the chain at the specified indices.
 * @param {ChainPointer} chainPtr
 * @param {BlockIndex[]} blockIndices
 * @return {Block[]} an array of blocks (same length as blockIndices)
 */
const getBlocks=(chainPtr,blockIndices)=>{
  return blockIndices.map(({chain_index:i})=>{
    return new Uint8Array(wasm.memory.buffer,chainPtr+i*BLOCK_SIZE,BLOCK_SIZE).slice();
  });
};
/**
 * Combines the blocks of the two chains.
 * @param {BlockIndex[]} indices1
 * @param {Block[]} blocks1
 * @param {BlockIndex[]} indices2
 * @param {Block[]} blocks2
 * @return {BlockArrayPointer} a pointer to an array of STEP_COUNT blocks (length STEP_COUNT * BLOCK_SIZE)
 */
const combineBlocks=(indices1,blocks1,indices2,blocks2)=>{
  const blockArrayPointer=wasm.alloc_blocks();
  const blockArray=new Uint8Array(wasm.memory.buffer,blockArrayPointer,STEP_COUNT*BLOCK_SIZE);
  indices1.forEach(({i},index)=>blockArray.set(blocks1[index],i*BLOCK_SIZE));
  indices2.forEach(({i},index)=>blockArray.set(blocks2[index],i*BLOCK_SIZE));
  return blockArrayPointer;
};
/**
 * Selects the proof reference indices for the specified block indices and parent blocks.
 * @param {BlockIndexPointer} indicesPtr
 * @param {BlockArrayPointer} parent_blocks_ptr
 * @return {{reference_indices_pointer:BlockIndexPointer,chain1:BlockIndex[],chain2:BlockIndex[]}}
 */
const selectReferenceIndices=(indicesPtr,parent_blocks_ptr)=>{
  const referenceIndicesPtr=wasm.select_reference_indices(indicesPtr, parent_blocks_ptr);
  const referenceIndices=new Uint32Array(wasm.memory.buffer,referenceIndicesPtr,STEP_COUNT);
  const chainIndices=[[],[]];
  referenceIndices.forEach((index,i)=>{
    chainIndices[Math.trunc(index/CHAIN_BLOCK_COUNT)].push({i,chain_index:index%CHAIN_BLOCK_COUNT})
  });
  const [chain1,chain2]=chainIndices;
  return {reference_indices_pointer:referenceIndicesPtr,chain1,chain2};
};
/**
 * Combines everything to build the proof.
 * This releases the memory of the state, the indices arrays, and block arrays.
 * @param {StatePointer} statePtr
 * @param {BlockIndexPointer} indicesPtr
 * @param {BlockIndexPointer} referenceIndicesPtr
 * @param {BlockArrayPointer} parentBlocksPtr
 * @param {BlockArrayPointer} referenceBlocksPtr
 * @return {Uint8Array} the proof
 */
const buildProof=(statePtr,indicesPtr,referenceIndicesPtr,parentBlocksPtr,referenceBlocksPtr)=>{
  let ptrAndLen=wasm.combine(statePtr,indicesPtr,referenceIndicesPtr,parentBlocksPtr,referenceBlocksPtr);
  let [ptr,len]=new Uint32Array(wasm.memory.buffer,ptrAndLen,2);
  return new Uint8Array(wasm.memory.buffer,ptr,len).slice();
};

/**
 * @param {Uint8Array} payload
 * @return {string}
 */
const hashHex=payload=>{
  let ptr=wasm.hash(payload.byteOffset,payload.byteLength);
  const hex=new Uint8Array(wasm.memory.buffer,ptr,16).toHex();
  wasm.free_hash(ptr);
  return hex;
}

/**
 * Everything together, without web worker for now.
 * @param {Uint8Array} nonce
 * @return {Uint8Array} the proof
 */
const proof=async(nonce)=>{
  const chain1Ptr=generateChain(0,nonce);
  const chain2Ptr=generateChain(1,nonce);
  const hashChain1Ptr=hashChain(chain1Ptr);
  const hashChain2Ptr=hashChain(chain2Ptr);
  const statePtr=buildState(hashChain1Ptr,hashChain2Ptr);
  const {indices_pointer:indicesPtr,chain1:i1,chain2:i2}=selectIndices(statePtr);
  const parentBlockArrayPtr=combineBlocks(i1,getBlocks(chain1Ptr,i1),i2,getBlocks(chain2Ptr,i2));
  const {reference_indices_pointer:referenceIndicesPtr,chain1:r1,chain2:r2}=selectReferenceIndices(indicesPtr,parentBlockArrayPtr);
  const referenceBlockArrayPtr=combineBlocks(r1,getBlocks(chain1Ptr,r1),r2,getBlocks(chain2Ptr,r2));

  const rootPtr = wasm.root(statePtr);
  const root = new Uint8Array(wasm.memory.buffer,rootPtr,16);
  const chain1=new Uint8Array(wasm.memory.buffer,chain1Ptr,CHAIN_BLOCK_COUNT*BLOCK_SIZE);
  console.log(`chain1: 0x${new Uint8Array(await crypto.subtle.digest('SHA-256',chain1)).toHex()}`);
  const chain2=new Uint8Array(wasm.memory.buffer,chain1Ptr,CHAIN_BLOCK_COUNT*BLOCK_SIZE);
  console.log(`chain2: 0x${new Uint8Array(await crypto.subtle.digest('SHA-256',chain2)).toHex()}`);
  const hashChain1=new Uint8Array(wasm.memory.buffer,hashChain1Ptr,CHAIN_BLOCK_COUNT*16);
  console.log(`hash chain1: 0x${new Uint8Array(await crypto.subtle.digest('SHA-256',hashChain1)).toHex()}`);
  const hashChain2=new Uint8Array(wasm.memory.buffer,hashChain2Ptr,CHAIN_BLOCK_COUNT*16);
  console.log(`hash chain2: 0x${new Uint8Array(await crypto.subtle.digest('SHA-256',hashChain2)).toHex()}`);
  console.log(`root: 0x${root.toHex()}`);

  const indices=new Uint16Array(wasm.memory.buffer,indicesPtr,STEP_COUNT);
  const referenceIndices=new Uint16Array(wasm.memory.buffer,referenceIndicesPtr,STEP_COUNT);
  const parentBlocks=new Uint8Array(wasm.memory.buffer,parentBlockArrayPtr,BLOCK_SIZE*STEP_COUNT);
  const referenceBlocks=new Uint8Array(wasm.memory.buffer,referenceBlockArrayPtr,BLOCK_SIZE*STEP_COUNT);
  const chains=[chain1,chain2];
  const hashChains=[hashChain1,hashChain2];
  for(let i=0;i<STEP_COUNT;++i){
    const index=indices[i];
    const parentIndex=index-1;
    const referenceIndex=referenceIndices[i];
    console.log(`step: ${i+1}/${STEP_COUNT}`);
    console.log(`index: ${index}`);
    console.log(`reference index: ${parentIndex}`);
    const blockChainIndices=[Math.trunc(index/CHAIN_BLOCK_COUNT),index%CHAIN_BLOCK_COUNT];
    console.log(`block chain indices: ${blockChainIndices[0]},${blockChainIndices[1]}`);
    const block=chains[blockChainIndices[0]].subarray(blockChainIndices[1]*BLOCK_SIZE,blockChainIndices[1]*BLOCK_SIZE+BLOCK_SIZE);
    const blockHash=hashChains[blockChainIndices[0]].subarray(blockChainIndices[1]*16,blockChainIndices[1]*16+16);
    console.log(`block hash (from hash chain): ${blockHash.toHex()}}`);
    console.log(`block hash (from chain): ${hashHex(block)}}`);
    const parentBlockChainIndices=[Math.trunc(parentIndex/CHAIN_BLOCK_COUNT),parentIndex%CHAIN_BLOCK_COUNT];
    console.log(`parent block chain indices: ${parentBlockChainIndices[0]},${parentBlockChainIndices[1]}`);
    const parentBlock=chains[parentBlockChainIndices[0]].subarray(parentBlockChainIndices[1]*BLOCK_SIZE,parentBlockChainIndices[1]*BLOCK_SIZE+BLOCK_SIZE);
    const parentBlockHash=hashChains[parentBlockChainIndices[0]].subarray(parentBlockChainIndices[1]*16,parentBlockChainIndices[1]*16+16);
    console.log(`parent block hash (from hash chain): ${parentBlockHash.toHex()}}`);
    console.log(`parent block hash (from parent blocks): ${hashHex(parentBlocks.subarray(i*BLOCK_SIZE,i*BLOCK_SIZE+BLOCK_SIZE))}`);
    console.log(`parent block hash (from chain): ${hashHex(parentBlock)}}`);
    const referenceBlockChainIndices=[Math.trunc(referenceIndex/CHAIN_BLOCK_COUNT),referenceIndex%CHAIN_BLOCK_COUNT];
    console.log(`reference block chain indices: ${referenceBlockChainIndices[0]},${referenceBlockChainIndices[1]}`);
    const referenceBlock=chains[referenceBlockChainIndices[0]].subarray(referenceBlockChainIndices[1]*BLOCK_SIZE,referenceBlockChainIndices[1]*BLOCK_SIZE+BLOCK_SIZE);
    const referenceBlockHash=hashChains[referenceBlockChainIndices[0]].subarray(referenceBlockChainIndices[1]*16,referenceBlockChainIndices[1]*16+16);
    console.log(`reference block hash (from hash chain): ${referenceBlockHash.toHex()}}`);
    console.log(`reference block hash (from reference blocks): ${hashHex(referenceBlocks.subarray(i*BLOCK_SIZE,i*BLOCK_SIZE+BLOCK_SIZE))}`);
    console.log(`reference block hash (from chain): ${hashHex(referenceBlock)}}`);
  }
  freeChain(chain1Ptr);
  freeChain(chain2Ptr);
  console.log(`memory pages: ${wasm.memory.buffer.byteLength/65536}`);
  return buildProof(statePtr,indicesPtr,referenceIndicesPtr,parentBlockArrayPtr,referenceBlockArrayPtr);
};

// const combineChains=(chain1,chain2)=>{
//   const res=wasm.combine_chains(chain1.byteOffset,chain2.byteOffset);
// };
export{proof};
