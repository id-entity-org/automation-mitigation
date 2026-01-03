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
 * Everything together, without web worker for now.
 * @param {Uint8Array} nonce
 * @return {Uint8Array} the proof
 */
const proof=nonce=>{
  const chain1Ptr=generateChain(0,nonce);
  const chain2Ptr=generateChain(1,nonce);
  const hashChain1Ptr=hashChain(chain1Ptr);
  const hashChain2Ptr=hashChain(chain2Ptr);
  const statePtr=buildState(hashChain1Ptr,hashChain2Ptr);
  const {indices_pointer:indicesPtr,chain1:i1,chain2:i2}=selectIndices(statePtr);
  const parentBlockArrayPtr=combineBlocks(i1,getBlocks(chain1Ptr,i1),i2,getBlocks(chain2Ptr,i2));
  const {reference_indices_pointer,chain1:r1,chain2:r2}=selectReferenceIndices(indicesPtr,parentBlockArrayPtr);
  const referenceBlockArrayPtr=combineBlocks(r1,getBlocks(chain1Ptr,r1),r2,getBlocks(chain2Ptr,r2));
  freeChain(chain1Ptr);
  freeChain(chain2Ptr);
  return buildProof(statePtr,indicesPtr,reference_indices_pointer,parentBlockArrayPtr,referenceBlockArrayPtr);
};

// const combineChains=(chain1,chain2)=>{
//   const res=wasm.combine_chains(chain1.byteOffset,chain2.byteOffset);
// };
export{generateChain,freeChain};
