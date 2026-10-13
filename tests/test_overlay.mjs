import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
export function sourceChecks(s) {
 const handler=s.slice(s.indexOf('static int __nocfi susfs_pre_handler'),s.indexOf('/* The members'));
 const register=s.slice(s.indexOf('int ksu_register_lsm_hook'),s.indexOf('void ksu_unregister_lsm_hook'));
 const teardown=s.slice(s.indexOf('void ksu_unregister_lsm_hook'),s.indexOf('int ksu_lsm_hook(struct'));
 return {
  noAllocatingGuard:!/(?:xa_store|GFP_KERNEL|GFP_ATOMIC|kmalloc|kzalloc)\s*[(,)]?/.test(s),
  noContinuationTrampoline:!s.includes('susfs_tramp_deny'),
  noCrossExceptionVerdict:!s.includes('susfs_verdict'),
  directReturn:handler.includes('regs_set_return_value(regs, (unsigned long)(long)verdict)')&&handler.includes('instruction_pointer_set(regs, procedure_link_pointer(regs))'),
  guardClearedBeforeReturn:handler.indexOf('this_cpu_write(susfs_probe_busy, false)')>handler.indexOf('(hook->replacement)')&&handler.indexOf('this_cpu_write(susfs_probe_busy, false)')<handler.indexOf('if (!verdict)'),
  resolvedSymbolEntry:s.includes('ksu_symbol_is_start(target, slot->symbol)'),
  exactEntryCheck:s.includes('(unsigned long)slot->probe.addr != target'),
  publishAfterRegistration:register.indexOf('smp_store_release(&slot->hook, hook)')>register.indexOf('ret = susfs_register_probe(slot)'),
  acquireReader:handler.includes('smp_load_acquire(&slot->hook)'),
  clearBeforeUnregister:teardown.indexOf('smp_store_release(&slot->hook, NULL)')>=0&&teardown.indexOf('smp_store_release(&slot->hook, NULL)')<teardown.indexOf('unregister_kprobe(&slot->probe)'),
  familyGate:[[5,10],[5,15],[6,1],[6,6],[6,12],[6,18]].every(([a,b])=>s.includes('KERNEL_VERSION('+a+', '+b+', 0)'))&&s.includes('defined(CONFIG_ARM64)'),
  nullOriginal:register.includes('!hook->replacement || hook->original'),
  noDuplicateSelectedEntry:s.includes('(unsigned long)susfs_slots[i].probe.addr == target'),
  thirteenMembers:[...s.matchAll(/SUSFS_SLOT\([a-z_]+\),/g)].length===13,
 };
}
function initialRegs(){ return {regs:Array.from({length:31},(_,i)=>BigInt(0x100+i)),pc:0x1000n,sp:0x9000n}; }
// A behavioral MODEL of the C handler, not compiled-kernel execution.
function handlerModel(r,cpus,cpu,callback,active=true){
 if(!active||cpus[cpu])return 0;
 cpus[cpu]=true;
 const v=callback(r.regs.slice(0,8));
 cpus[cpu]=false;
 if(!v)return 0;
 r.regs[0]=BigInt.asUintN(64,BigInt(v));
 r.pc=r.regs[30];
 return 1;
}
export async function run(baselinePath,candidatePath){
 const baseline=sourceChecks(await fs.readFile(baselinePath,'utf8'));
 const candidate=sourceChecks(await fs.readFile(candidatePath,'utf8'));
 assert.ok(Object.values(baseline).some(v=>!v),'baseline must expose regressions');
 for(const [k,v] of Object.entries(candidate))assert.equal(v,true,k);
 let models=0;
 for(const verdict of [0,-2,-13,1]){
  const r=initialRegs(),before={regs:r.regs.slice(),pc:r.pc,sp:r.sp},busy=[false,false];
  let calls=0; const result=handlerModel(r,busy,0,(args)=>{calls++;assert.deepEqual(args,before.regs.slice(0,8));return verdict;});
  assert.equal(calls,1);assert.equal(result,verdict?1:0);assert.deepEqual(busy,[false,false]);
  assert.equal(r.sp,before.sp);assert.deepEqual(r.regs.slice(1),before.regs.slice(1));
  assert.equal(r.pc,verdict?before.regs[30]:before.pc);assert.equal(r.regs[0],verdict?BigInt.asUintN(64,BigInt(verdict)):before.regs[0]);models++;
 }
 for(const active of [false,true]){
  const r=initialRegs(),before={regs:r.regs.slice(),pc:r.pc,sp:r.sp};let called=false;
  const busy=[active,false];assert.equal(handlerModel(r,busy,0,()=>{called=true;return -2},active),0);
  assert.equal(called,false);assert.deepEqual(r,before);models++;
 }
 // Independent CPUs and nested entry must not overwrite another result.
 const r0=initialRegs(),r1=initialRegs(),busy=[false,false];
 handlerModel(r0,busy,0,()=>{assert.equal(handlerModel(initialRegs(),busy,0,()=>assert.fail('nested callback')),0);handlerModel(r1,busy,1,()=>-13);return -2});
 assert.equal(r0.regs[0],BigInt.asUintN(64,-2n));assert.equal(r1.regs[0],BigInt.asUintN(64,-13n));assert.deepEqual(busy,[false,false]);models++;
 return {baseline,candidate,sourceChecksPassed:Object.values(candidate).filter(Boolean).length,behavioralModelCasesPassed:models,compiledC:false,deviceTest:false,result:'PASS: source contracts and behavioral models; kernel compilation/device execution not tested'};
}
