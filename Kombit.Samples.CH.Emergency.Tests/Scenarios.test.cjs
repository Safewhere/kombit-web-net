const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const source = fs.readFileSync(require('node:path').join(__dirname, '../Kombit.Samples.CH.WebsiteDemo/EmergencyAssets/scenarios.js'), 'utf8');
class Element {
    constructor() { this.children = []; this.listeners = {}; this.dataset = {}; }
    append(...items) { this.children.push(...items); }
    prepend(...items) { this.children.unshift(...items); }
    replaceChildren() { this.children = []; }
    setAttribute(name, value) { this[name] = value; }
    addEventListener(name, fn) { this.listeners[name] = fn; }
}
const flatten = node => [node, ...node.children.flatMap(flatten)];
function run(initial) {
    const values = new Map([['real-key-marker', 'preserve'], ['kombit-demo-scenarios-v1', JSON.stringify(initial)]]);
    const body = new Element(), link = new Element();
    let loaded;
    const routes = [];
    const ctx = { URL, Date, JSON, Array, location: { href: 'https://demo.test/app/MyPage.aspx', assign: value => routes.push(value) },
        sessionStorage: { getItem: key => values.get(key), setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) },
        document: { body, createElement: () => new Element(), addEventListener: (_, fn) => loaded = fn, getElementById: () => ({dataset:{root:'/app/'}}), querySelectorAll: () => [link] }
    };
    ctx.window = ctx; vm.runInNewContext(source, ctx); loaded();
    return { ctx, body, link, values, routes, button: text => flatten(body).find(item => item.textContent === text) };
}
let r = run({scenario:'forced'}), clicks = 0;
r.ctx.EmergencyDemo.setup({click:()=>clicks++}, false);
r.ctx.EmergencyDemo.setup({click:()=>clicks++}, false);
assert.equal(clicks, 1, 'forced setup opens once, not on every widget refresh');
r = run({scenario:'forced'}); clicks = 0;
r.ctx.EmergencyDemo.setup({click:()=>clicks++}, true); assert.equal(clicks, 0, 'active keys never cause reenrollment');
r = run({scenario:'optional'}); r.ctx.EmergencyDemo.setup({click:()=>clicks++}, false); assert.equal(clicks, 0);
r = run({scenario:'outage'}); let prevented = false;
r.link.listeners.click({preventDefault:()=>prevented=true}); assert(prevented); assert(r.ctx.EmergencyDemo.outage());
r.button('Reset scenario').listeners.click(); assert.equal(r.values.get('real-key-marker'), 'preserve');
assert(!r.values.has('kombit-demo-scenarios-v1')); assert.equal(r.routes[0], 'https://demo.test/app/MyPage.aspx');
r = run({});
const row = flatten(r.body).find(item => item.children.some(child => child.textContent === 'Renew after normal login'));
row.listeners.click(); assert.match(r.routes[0], /\/app\/LoginOptions.aspx\?ReturnUrl=%2Fapp%2FMyPage.aspx$/);
assert(!source.includes('localStorage'), 'scenario control must not modify real browser key markers');
console.log('Scenarios: isolation, forced/optional setup, outage, reset and virtual-directory routing passed');
