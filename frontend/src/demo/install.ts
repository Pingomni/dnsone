// Demo build only (VITE_DEMO=true, `npm run build:demo`): the console runs unchanged, and every /api
// request it makes (fetch, live panels, download links) is answered in the browser by the demo engine.
import { DemoError, demoDownload, demoRequest, resetDemo } from './engine';

const LATENCY = 120;

function json(status: number, body: unknown): Response {
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function isApi(url: string): boolean {
    return new URL(url, window.location.origin).pathname.startsWith('/api/');
}

export function installDemo(): void {
    const realFetch = window.fetch.bind(window);
    window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        if (!isApi(url)) return realFetch(input, init);
        const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
        let body: unknown;
        try {
            body = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
        } catch {
            body = undefined;
        }
        await new Promise((resolve) => window.setTimeout(resolve, LATENCY));
        try {
            const path = new URL(url, window.location.origin).pathname;
            if (path === '/api/cluster/secondary-config') {
                const file = demoDownload(url);
                return new Response(file?.body ?? '', { status: 200, headers: { 'Content-Type': 'text/plain' } });
            }
            const out = demoRequest(method, url, body);
            if (path === '/api/auth/logout') window.setTimeout(() => window.location.assign('/'), 50);
            return json(method === 'POST' && /\/(zones|records|rules|blocklists|users|groups|networks|tokens)$/.test(path) ? 201 : 200, out);
        } catch (e) {
            if (e instanceof DemoError) return json(e.status, { message: e.message, errors: e.errors });
            return json(500, { message: 'The demo could not answer this.', errors: {} });
        }
    };

    // Download links (zone file, backup): the file is made in the browser.
    document.addEventListener('click', (event) => {
        const link = (event.target as Element | null)?.closest?.('a[href^="/api/"]') as HTMLAnchorElement | null;
        if (!link) return;
        event.preventDefault();
        const file = demoDownload(link.getAttribute('href') ?? '');
        if (!file) return;
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([file.body], { type: file.type }));
        a.download = file.name;
        a.click();
        window.setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    }, true);

    // A small notice that this is the demo, with a way to start over.
    const pill = document.createElement('div');
    pill.className = 'demo-pill';
    pill.setAttribute('role', 'note');
    pill.innerHTML = '<strong>Demo</strong><span>Sample data · changes stay in this browser</span>';
    const reset = document.createElement('button');
    reset.type = 'button';
    reset.textContent = 'Reset';
    reset.addEventListener('click', () => {
        resetDemo();
        window.location.assign('/');
    });
    pill.append(reset);
    document.body.append(pill);
}
