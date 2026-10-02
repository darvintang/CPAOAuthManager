// Created by Darvin.
// Run the actual embedded UI with synthetic CPAMC storage; no real credentials are read.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto').webcrypto;
const keyA=require('node:crypto').createHash('sha256').update('cpa\0a').digest('hex');
const keyB=require('node:crypto').createHash('sha256').update('cpa\0b').digest('hex');
const source = fs.readFileSync(path.join(__dirname, '..', 'main.go'), 'utf8');
const script = source.match(/<script>([\s\S]*?)<\/script>/)[1];
const origin = 'http://127.0.0.1:8317';
const userAgent = 'CPAMC test';
const manualStorageKey = 'cpa-oauth-manager.management-key';

function encoded(value) {
  const bytes = Buffer.from(JSON.stringify(value));
  const mask = Buffer.from('cli-proxy-api-webui::secure-storage|127.0.0.1:8317|' + userAgent);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] ^= mask[i % mask.length];
  }
  return 'enc::v1::' + bytes.toString('base64');
}

async function run(values, status = 200, blocked = false, browserLanguage = 'en') {
  const storage = new Map(Object.entries(values));
  const elements = new Map();
  const requests = [];
  const listeners = {};
  const root = {lang: '', dataset: {}};
  const payload={authority_state:'available',accounts:[{config_id:keyA,label:'A',limit:2,reserved:1,in_flight:0,warm_flight:0},{config_id:keyB,label:'B',limit:3,reserved:1,in_flight:0,warm_flight:0}],summary:{total:{in_flight:0,limit:5},warm_reserved:{in_flight:0,reserved:2}}};
  let config={max_concurrency:2,enabled:true,credential_limits:{[keyB]:3},other:'preserve'};
  let poll;
  const files=[{id:'a',name:'a.json',email:'A',priority:5,weight:2},{id:'b',name:'b.json',email:'B',priority:0,weight:1,disabled:true}];
  let failFieldSave=false;
  let failConfigSave=false;
  const getElement = id => {
    if (!elements.has(id)) {
      const element={value:'',dataset:{},events:{},writes:[],addEventListener(name,callback){this.events[name]=callback;},setAttribute(name,value){this[name]=value;},querySelectorAll(){return [];},contains(){return false;}};
      for(const field of ['textContent','innerHTML']){let value='';Object.defineProperty(element,field,{get(){return value;},set(next){value=String(next);element.writes.push([field,value]);}})}
      elements.set(id,element);
    }
    return elements.get(id);
  };
  const labels = [...source.matchAll(/data-i18n="([^"]+)"/g)].map(match => ({dataset: {i18n: match[1]}, textContent: ''}));
  vm.runInNewContext(script, {
    URL, TextEncoder, TextDecoder, Uint8Array, atob, crypto,
    location: {host: '127.0.0.1:8317', origin}, navigator: {userAgent, language: browserLanguage},
    document: {getElementById: getElement, documentElement: root, querySelectorAll(selector) {return selector==='[data-i18n]'?labels:[];}}, setInterval(callback) {poll=callback;},
    window: {addEventListener(name, callback) {listeners[name] = callback;}, matchMedia() {return {matches: false};}},
    localStorage: {
      getItem(key) {
        if (blocked) {
          throw new Error('Storage denied');
        }
        return storage.get(key) ?? null;
      },
      setItem(key, value) {storage.set(key, value);},
      removeItem(key) {storage.delete(key);}
    },
    async fetch(url, options) {
      requests.push({url, options});
      if(url.endsWith('/usage')){return {ok:status===200,status,async json(){return payload;}}}
      if(url.endsWith('/auth-files')){return {ok:true,status:200,async json(){return {files};}}}
      if(url.endsWith('/auth-files/fields')){if(failFieldSave){return {ok:false,status:500}}const patch=JSON.parse(options.body);Object.assign(files.find(f=>f.name===patch.name),patch);return {ok:true,status:200};}
      if(options.method==='PUT'){if(failConfigSave){return {ok:false,status:500}}config=JSON.parse(options.body)}
      return {ok:true,status:200,async json(){return config;}};
    }
  });
  await new Promise(resolve => setTimeout(resolve,30));
  return {storage,elements,requests,root,labels,listeners,poll,payload,getConfig:()=>config,files,setFailures(fields,config){failFieldSave=fields;failConfigSave=config;}};
}

(async () => {
  const auth = {state: {apiBase: origin, managementKey: 'host-test-key'}};
  for (const values of [
    {'cli-proxy-auth': JSON.stringify(auth)},
    {'cli-proxy-auth': encoded(auth)},
    {'managementKey': 'host-test-key'},
    {'managementKey': JSON.stringify('host-test-key')},
    {'managementKey': encoded('host-test-key')},
    {'cli-proxy-auth': encoded(auth), [manualStorageKey]: 'manual-test-key'}
  ]) {
    const result = await run(values);
    assert.equal(result.requests.length, 3);
    assert.equal(result.requests[0].url, '/v0/management/plugins/cpa-oauth-manager/usage');
    assert.equal(result.requests[0].options.headers['X-Management-Key'], 'host-test-key');
    assert.equal(result.elements.get('management-key').value, values[manualStorageKey] || '');
    assert.deepEqual(Object.fromEntries(result.storage), values);
    assert.equal(result.elements.get('key-status').textContent, 'Using Management Center authentication.');
  }
  for (const values of [
    {}, {'cli-proxy-auth': 'enc::v1::!'},
    {'cli-proxy-auth': encoded({state: {...auth.state, apiBase: 'https://other.example'}}), managementKey: 'legacy-test-key'},
    {apiBase: JSON.stringify('https://other.example'), managementKey: 'legacy-test-key'}
  ]) {
    const result = await run(values);
    assert.equal(result.requests.length, 0);
    assert.match(result.elements.get('state').textContent, /Management key required/);
    assert.equal(result.elements.get('settings').hidden, false);
    assert.equal(result.elements.get('settings').open, true);
  }
  assert.equal((await run({'cli-proxy-auth': encoded(auth)}, 200, true)).requests.length, 0);
  const manual = await run({[manualStorageKey]: 'manual-test-key'});
  assert.equal(manual.requests[0].options.headers['X-Management-Key'], 'manual-test-key');
  for (const status of [401, 403]) {
    const result = await run({'cli-proxy-auth': encoded(auth)}, status);
    assert.equal(result.elements.get('state').textContent, 'Management authentication required.');
    assert.equal(result.elements.get('summary-total').textContent, '--');
    assert.equal(result.elements.get('settings').hidden, false);
    assert.equal(result.elements.get('settings').open, true);
  }
  for (const [language, title, authText] of [
    ['zh-CN', '凭证管理', '已自动使用管理中心登录凭据。'],
    ['zh-TW', '憑證管理', '已自動使用管理中心登入憑據。'],
    ['en', 'Credential Manager', 'Using Management Center authentication.'],
    ['ru', 'Управление учётными данными', 'Используются учётные данные центра управления.']
  ]) {
    const result = await run({'cli-proxy-auth': encoded(auth), 'cli-proxy-language': JSON.stringify({state: {language}}), 'cli-proxy-theme': JSON.stringify({state: {theme: 'dark'}})});
    assert.equal(result.root.lang, language);
    assert.equal(result.root.dataset.theme, 'dark');
    assert.equal(result.labels.find(el => el.dataset.i18n === 'Credential Manager').textContent, title);
    assert.equal(result.elements.get('key-status').textContent, authText);
    assert.equal(result.elements.get('settings').open, false);
    assert.equal(result.elements.get('settings').hidden, true);
    result.storage.set('cli-proxy-language', JSON.stringify({state: {language: 'en'}}));
    result.listeners.storage({key: 'cli-proxy-language'});
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(result.root.lang, 'en');
  }
  assert.equal((await run({}, 200, false, 'zh-HK')).root.lang, 'zh-TW');
  assert.equal((await run({}, 200, false, 'fr')).root.lang, 'en');
  const interaction=await run({'cli-proxy-auth':encoded(auth)});
  const {elements,requests}=interaction;
  const edit=(key,field,value)=>elements.get('accounts').events.input({target:{dataset:{key,field},value}});
  edit(keyA,'limit','7');edit(keyA,'priority','9');edit(keyB,'weight','4');
  const beforeSave=requests.length;
  const rowWrites=elements.get('accounts').writes.length;
  const stateWrites=elements.get('state').writes.length;
  await interaction.poll();
  assert.equal(elements.get('accounts').writes.length,rowWrites);
  assert.equal(elements.get('state').writes.length,stateWrites);
  assert.equal(requests.filter(r=>r.options.method==='PATCH'||r.options.method==='PUT').length,0);
  await elements.get('save-all').onclick();
  assert.equal(interaction.getConfig().credential_limits[keyA],7);
  assert.equal(interaction.getConfig().credential_limits[keyB],3);
  assert.equal(interaction.getConfig().other,'preserve');
  assert.equal(interaction.files[0].priority,9);
  assert.equal(interaction.files[1].weight,4);
  const failure=await run({'cli-proxy-auth':encoded(auth)});
  failure.elements.get('accounts').events.input({target:{dataset:{key:keyA,field:'weight'},value:'3'}});
  failure.setFailures(true,false);
  await failure.elements.get('save-all').onclick();
  assert.match(failure.elements.get('config-status').textContent,/Some changes/);
  assert.equal(failure.elements.get('save-all').disabled,false);
  failure.setFailures(false,false);
  await failure.elements.get('save-all').onclick();
  assert.equal(failure.files[0].weight,3);
  for(const value of ['0','-1','1.5','1000001']){
    const invalid=await run({'cli-proxy-auth':encoded(auth)});
    invalid.elements.get('accounts').events.input({target:{dataset:{key:keyA,field:'limit'},value}});
    const before=invalid.requests.length;
    await invalid.elements.get('save-all').onclick();
    assert.equal(invalid.requests.length,before);
  }
  console.log('Management authentication, language, per-credential settings and quiet refresh checks passed');
})().catch(error => {console.error(error); process.exitCode = 1;});
