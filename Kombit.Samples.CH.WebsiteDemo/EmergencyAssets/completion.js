(function () {
    'use strict';
    const page = document.getElementById('emergency-completion');
    if (!page) return;
    const status = document.getElementById('completion-status');
    const proceed = document.getElementById('completion-continue');
    const markerKey = 'saml-emergency-login-v1';
    function unavailable(message) {
        status.textContent = message;
        proceed.hidden = false;
    }
    async function complete() {
        if (!page.dataset.csrf || !window.fetch) {
            unavailable('Your normal login succeeded. Emergency access could not be refreshed.');
            return;
        }
        let markers;
        try {
            const stored = JSON.parse(localStorage.getItem(markerKey) || '[]');
            markers = Array.isArray(stored) ? stored.filter(item => item && typeof item.binding_id === 'string'
                && item.binding_id.length > 0 && item.binding_id.length <= 128) : [];
        } catch (_) {
            unavailable('Your normal login succeeded. Browser storage is unavailable, so your Passticket was not renewed.');
            return;
        }
        // Include stale expiry markers: only the server determines whether the binding is active.
        const ids = [...new Set(markers.map(item => item.binding_id))].slice(-10);
        try {
            const response = await fetch(page.dataset.api + '?op=renew-after-login', {
                method: 'POST', credentials: 'same-origin', redirect: 'error',
                headers: { 'Content-Type': 'application/json', 'X-Emergency-CSRF': page.dataset.csrf },
                body: JSON.stringify({ binding_ids: ids }),
            });
            const result = await response.json();
            if (window.EmergencyDemo) window.EmergencyDemo.renewal(response.ok ? result : { outcome: 'failed' });
            if (!response.ok) {
                const reference = result.reference_id || response.headers.get('X-Emergency-Reference');
                unavailable('Your normal login succeeded, but your Passticket was not renewed. Its previous validity has not been extended.'
                    + (reference ? ' Support reference: ' + reference : ''));
                return;
            }
            if (result.outcome === 'renewed') {
                const updated = markers.filter(item => item.binding_id !== result.binding_id)
                    .map(item => ({ binding_id: item.binding_id, expires_at: item.expires_at }));
                updated.push({ binding_id: result.binding_id, expires_at: result.expires_at });
                try { localStorage.setItem(markerKey, JSON.stringify(updated)); }
                catch (_) {
                    unavailable('Your Passticket was renewed, but this browser could not save its emergency-login marker.');
                    return;
                }
            } else if (result.outcome !== 'skipped') {
                unavailable(result.outcome === 'pending'
                    ? 'Another request is refreshing your Passticket. You can continue; this page will not issue a second renewal.'
                    : 'Your normal login succeeded. The Passticket renewal did not complete; try again after your next normal login.');
                return;
            }
            location.replace(page.dataset.return);
        } catch (_) {
            unavailable('Your normal login succeeded. Renewal could not be confirmed. It will be attempted after your next normal login.');
        }
    }
    complete();
})();
