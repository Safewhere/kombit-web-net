const fs = require('node:fs'), vm = require('node:vm'), path = require('node:path'), assert = require('node:assert/strict');
const source = fs.readFileSync(path.join(__dirname, '../Kombit.Samples.CH.WebsiteDemo/EmergencyAssets/completion.js'), 'utf8');
async function run(outcome, marker = [{ binding_id: 'mine', expires_at: 1 }], failure = false) {
    const requests = [], redirects = [];
    const nodes = {
        'emergency-completion': { dataset: { api: '/virtual/EmergencyApi.ashx', csrf: 'csrf', return: '/virtual/Other.aspx?x=1' } },
        'completion-status': {}, 'completion-continue': { hidden: true },
    };
    let saved = JSON.stringify(marker);
    const ctx = { document: { getElementById: id => nodes[id] },
        localStorage: { getItem: () => { if (failure === 'storage') throw Error(); return saved; }, setItem: (_, value) => saved = value },
        location: { replace: value => redirects.push(value) },
        navigator: { credentials: { create: () => assert.fail('renewal must not create a passkey'), get: () => assert.fail('renewal must not prompt') } },
        fetch: async (url, init) => {
            requests.push({ url, init });
            if (failure === 'network') throw Error();
            return { ok: !failure, headers: { get: () => 'reference' }, json: async () => ({ outcome,
                binding_id: 'mine', expires_at: 2000000000, reference_id: 'reference' }) };
        }, console, Set, JSON, Array };
    ctx.window = ctx;
    vm.runInNewContext(source, ctx);
    await new Promise(resolve => setImmediate(resolve));
    return { requests, redirects, nodes, saved };
}
(async () => {
    let r = await run('renewed');
    assert.equal(r.requests.length, 1);
    assert.equal(r.requests[0].url, '/virtual/EmergencyApi.ashx?op=renew-after-login');
    assert.equal(r.requests[0].init.headers['X-Emergency-CSRF'], 'csrf');
    assert.deepEqual(JSON.parse(r.requests[0].init.body), { binding_ids: ['mine'] });
    assert.deepEqual(r.redirects, ['/virtual/Other.aspx?x=1']);
    assert.deepEqual(JSON.parse(r.saved), [{ binding_id: 'mine', expires_at: 2000000000 }]);
    r = await run('skipped', []);
    assert.equal(r.redirects.length, 1);
    assert.deepEqual(JSON.parse(r.requests[0].init.body), { binding_ids: [] });
    for (const mode of ['network', 'http', 'storage']) {
        r = await run('failed', undefined, mode);
        assert.equal(r.redirects.length, 0);
        assert.equal(r.nodes['completion-continue'].hidden, false);
        assert.match(r.nodes['completion-status'].textContent, /normal login succeeded/);
        assert(r.requests.length <= 1, 'no blind retry');
        assert.equal(JSON.parse(r.saved)[0].expires_at, 1);
    }
    for (const outcome of ['pending', 'failed']) {
        r = await run(outcome);
        assert.equal(r.requests.length, 1);
        assert.equal(r.nodes['completion-continue'].hidden, false);
    }
    console.log('post-login renewal: no passkey prompt, marker update, return path and failure handling passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
