import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, stat, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setupOperator } from './setup-operator.mjs';

test('initial setup writes private distinct credentials without touching an existing setup',async t=>{
 const root=await mkdtemp(join(await realpath(tmpdir()),'relay-setup-test-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const stateDirectory=join(root,'private');const options={rendezvousUrl:'https://relay.example.com',packageDirectory:join(root,'output','package'),stateDirectory};
 await setupOperator(options);
 const state=JSON.parse(await readFile(join(stateDirectory,'operator.json'),'utf8'));
 const secrets=JSON.parse(await readFile(join(stateDirectory,'worker-secrets.json'),'utf8'));
 const mcp=JSON.parse(await readFile(join(stateDirectory,'mcp-config.json'),'utf8')).mcpServers.relay;
 assert.match(secrets.PROVISION_KEY,/^[a-f0-9]{64}$/);assert.match(secrets.READ_KEY,/^[a-f0-9]{48}$/);
 assert.notEqual(secrets.READ_KEY,secrets.PROVISION_KEY);assert.equal(state.provision_key,secrets.PROVISION_KEY);
 assert.equal(mcp.env.RELAY_RENDEZVOUS_READ_KEY,secrets.READ_KEY);assert.equal(state.package.volume_uuid,undefined);
 assert.equal((await stat(stateDirectory)).mode&0o777,0o700);
 for(const name of ['operator.json','worker-secrets.json','mcp-config.json'])assert.equal((await stat(join(stateDirectory,name))).mode&0o777,0o600);
 await assert.rejects(setupOperator(options));assert.deepEqual(JSON.parse(await readFile(join(stateDirectory,'operator.json'),'utf8')),state);
});
test('setup rejects a non-HTTPS rendezvous before creating credentials',async t=>{
 const root=await mkdtemp(join(await realpath(tmpdir()),'relay-setup-test-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const directory=join(root,'private');await assert.rejects(setupOperator({rendezvousUrl:'http://example.com',packageDirectory:join(root,'package'),stateDirectory:directory}));
 await assert.rejects(stat(directory));
});
