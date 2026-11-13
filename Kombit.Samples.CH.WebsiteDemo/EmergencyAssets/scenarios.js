(function () {
    'use strict';
    // Demo conditions affect this tab's presentation, never server authentication or stored keys.
    const storageKey = 'kombit-demo-scenarios-v1';
    const allowed = ['forced', 'optional', 'outage', 'emergency', 'renewal'];
    let state = {};
    try { state = JSON.parse(sessionStorage.getItem(storageKey) || '{}'); } catch (_) {}
    if (!state || !allowed.includes(state.scenario)) state = {};
    let history = Array.isArray(state.history) ? state.history.filter(item => typeof item === 'string').slice(-12) : [];
    function save() { try { sessionStorage.setItem(storageKey, JSON.stringify({ scenario: state.scenario, opened: state.opened, history })); } catch (_) {} }
    function record(message) { history.push(new Date().toLocaleTimeString() + ' · ' + message); history = history.slice(-12); save(); renderHistory(); }
    function reset() { state = {}; history = []; try { sessionStorage.removeItem(storageKey); } catch (_) {} }
    let log;
    function renderHistory() { if (log) { log.replaceChildren(); history.forEach(message => log.append(node('li', '', message))); } }
    window.EmergencyDemo = {
        outage: () => state.scenario === 'outage',
        authenticated() { record('Real emergency authentication succeeded: the server verified the passkey and accepted the session.'); },
        setup(trigger, ready) {
            if (!['forced', 'optional'].includes(state.scenario) || state.opened) return;
            state.opened = true; save();
            if (ready) record('Setup not started: this browser already has an active key. Use a fresh browser/account to demonstrate enrollment.');
            else if (trigger && state.scenario === 'forced') { record('Setup dialog opened. Enrollment still requires your confirmation.'); trigger.click(); }
            else record('Optional setup reminder shown.');
        },
        renewal(result) {
            record(result.outcome === 'renewed' ? 'Real Passticket renewal succeeded. Valid until ' + new Date(result.expires_at * 1000).toLocaleString()
                : result.outcome === 'skipped' ? 'Renewal skipped: no eligible key for this normal login.' : 'Renewal outcome: ' + (['pending', 'failed'].includes(result.outcome) ? result.outcome : 'unconfirmed'));
        }
    };
    function node(tag, cls, text) { const item = document.createElement(tag); item.className = cls; if (text) item.textContent = text; return item; }
    function button(text, work) { const item = node('button', '', text); item.type = 'button'; item.addEventListener('click', work); return item; }
    document.addEventListener('DOMContentLoaded', () => {
        const script = document.getElementById('demo-scenarios-script');
        if (!script) return;
        const root = new URL(script.dataset.root, location.href);
        const route = path => new URL(path, root).href;
        const panel = node('aside', 'scenario-panel', ''); panel.setAttribute('aria-label', 'Demo scenarios');
        const toggle = button('Scenarios', () => { content.hidden = !content.hidden; toggle.setAttribute('aria-expanded', String(!content.hidden)); });
        toggle.className = 'scenario-toggle'; toggle.setAttribute('aria-expanded', 'false');
        const content = node('div', 'scenario-content', ''); content.hidden = true;
        content.id = 'scenario-content'; toggle.setAttribute('aria-controls', content.id);
        const current = node('p', 'scenario-current', state.scenario ? 'Active: ' + state.scenario : 'Choose a demo journey');
        content.append(current);
        function run(id) {
            state = { scenario: id }; history = []; save();
            record(id === 'outage' ? 'Simulated outage enabled for this tab’s login screen. CH2 remains running; passkey verification is real.' : 'Real flow selected: ' + id);
            const exit = document.getElementById('exit');
            if (exit && typeof exit.click === 'function') {
                record('Ending the previous emergency session. Continue with Sign in again on the session-ended page.');
                exit.click();
                return;
            }
            location.assign(route('LoginOptions.aspx?ReturnUrl=' + encodeURIComponent(new URL('MyPage.aspx', root).pathname)));
        }
        const groups = [
            ['Set up emergency access', [['forced', 'Forced', 'Real flow · Open setup after normal login'], ['optional', 'Not forced', 'Real flow · Show the setup reminder']]],
            ['Emergency login', [['outage', 'Normal login unavailable', 'Simulated outage · Real authentication'], ['emergency', 'Emergency with a key', 'Real flow · Confirm your existing passkey']]],
            ['Renew emergency access', [['renewal', 'Renew after normal login', 'Real flow · No extra passkey prompt']]]
        ];
        groups.forEach(([name, choices]) => {
            const group = node('details', 'scenario-group', ''); group.append(node('summary', '', name));
            choices.forEach(([id, label, description]) => { const action = button('', () => run(id)); action.append(node('strong', '', label), node('span', '', description)); group.append(action); });
            content.append(group);
        });
        const backstage = node('details', 'scenario-group', ''); backstage.append(node('summary', '', 'Behind the scenes'));
        backstage.append(node('p', '', 'Real results only. Setup and emergency login still require your passkey. Existing keys are never reset.'));
        log = node('ol', 'scenario-log', ''); backstage.append(log); content.append(backstage); renderHistory();
        content.append(button('Reset scenario', () => { reset(); location.assign(route('MyPage.aspx')); }));
        panel.append(toggle, content); document.body.append(panel);
        if (/\/LoginOptions\.aspx$/i.test(location.pathname || '') && !document.getElementById('emergency-login-option')) {
            const notice = node('p', 'scenario-notice', 'Emergency login is not currently offered. If an emergency session is already active, sign out locally before starting a new journey. Otherwise, check the emergency-access configuration. ');
            const sessionLink = node('a', '', 'Open emergency session'); sessionLink.href = route('EmergencyHome.aspx'); notice.append(sessionLink);
            const main = document.querySelector('.login-page'); if (main) main.append(notice);
        }
        if (state.scenario) {
            const banner = node('div', 'scenario-banner', state.scenario === 'outage' ? 'DEMO · Simulated normal-login outage · Real emergency authentication' : 'DEMO · Real flow: ' + state.scenario);
            banner.append(button('Exit scenario', () => { reset(); location.assign(route('MyPage.aspx')); })); document.body.prepend(banner);
        }
        if (state.scenario === 'outage') document.querySelectorAll('.idp-option[href]').forEach(link => {
            link.setAttribute('aria-disabled', 'true');
            link.addEventListener('click', event => { event.preventDefault(); record('Normal login withheld by the simulated outage. Exit the scenario to restore it.'); content.hidden = false; toggle.setAttribute('aria-expanded', 'true'); });
        });
    });
})();
