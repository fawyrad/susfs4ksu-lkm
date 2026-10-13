import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import {sourceChecks,run} from './test_overlay.mjs';
const [mode,file,baseline]=process.argv.slice(2);
if(!['baseline','modified','rollback'].includes(mode)||!file){
 console.error('usage: node test_cli.mjs baseline|modified|rollback FILE [BASELINE]');
 process.exit(2);
}
const bytes=await fs.readFile(file);
const checks=sourceChecks(bytes.toString('utf8'));
const pass=Object.values(checks).filter(Boolean).length;
const fail=Object.entries(checks).filter(([,v])=>!v).map(([k])=>k);
console.log(mode.toUpperCase()+': source contracts '+pass+'/'+Object.keys(checks).length+' passed');
console.log('SHA256 '+crypto.createHash('sha256').update(bytes).digest('hex'));
if(fail.length)console.log('FAILED '+fail.join(', '));
if(mode==='modified'){
 if(fail.length){process.exitCode=1;}else{
  const result=await run(baseline,file);
  console.log('MODEL: '+result.behavioralModelCasesPassed+'/7 passed');
  console.log('COMPILED_C=false DEVICE_TEST=false');
 }
}else if(mode==='rollback'){
 const original=await fs.readFile(baseline);
 if(!bytes.equals(original)){
  console.error('ROLLBACK: baseline bytes differ');process.exitCode=1;
 }else{
  console.log('ROLLBACK: byte-identical baseline and baseline contract failures restored');
  console.log('COMPILED_C=false DEVICE_TEST=false');
 }
}else{
 console.log('BASELINE: expected original design failures observed');
 process.exitCode=fail.length?1:0;
}
