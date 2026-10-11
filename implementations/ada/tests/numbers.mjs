// Independent ECMAScript RFC 8785 number oracle; no VH-Log implementation code.
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import assert from 'node:assert/strict';
const driver = spawn('./bin/vh-log-driver', [], {stdio:['pipe','pipe','inherit']});
const lines = createInterface({input:driver.stdout})[Symbol.asyncIterator]();
let state = 0x123456789abcdef0n;
const mask = (1n<<64n)-1n;
const values = [0,-0,Number.MIN_VALUE,Number.MAX_VALUE,1e-6,1e-7,1e20,1e21];
const bytes=Buffer.alloc(8);
for(let i=0;i<5000;i++){
 state=(state*6364136223846793005n+1442695040888963407n)&mask;
 bytes.writeBigUInt64LE(state);
 const n=bytes.readDoubleLE();if(Number.isFinite(n))values.push(n);
}
for(let i=0;i<values.length;i+=100){
 const group=values.slice(i,i+100);const text=JSON.stringify(group);
 driver.stdin.write(JSON.stringify({id:i,op:'jcs',input:{text}})+'\n');
 const reply=JSON.parse((await lines.next()).value);
 assert.equal(reply.ok,true,JSON.stringify(reply));
 assert.equal(reply.result.output,text);
}
driver.stdin.end();
console.log(`${values.length} IEEE binary64 values matched ECMAScript`);
