import { useEffect, useRef, useState, type ReactNode } from 'react';
import { formatInZone, toServerTime, useServerTimezone } from '@/lib/clock';
import { slugKey } from '@/lib/format';

type LiveState = 'live' | 'paused' | 'error' | 'expired';

const clock = (ms: number, timeZone: string) => formatInZone(toServerTime(ms), timeZone, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
const ago = (ms: number) => {
    const s = Math.max(0, Math.round(ms / 1000));
    return s < 60 ? `${s}s ago` : `${Math.floor(s / 60)}m ago`;
};

/**
 * Panel whose data is refreshed from a JSON endpoint (legacy livePanel). Polling pauses while the tab is
 * hidden, a dialog is open, or the operator points at or is focused inside the panel, so rows never move
 * under a cursor about to click. Failures back off exponentially (max 5 min); an expired login stops it.
 */
export function LivePanel<T>({ title, url, interval, initial, render, headerLink, className = '', onData }: {
    title: string;
    url: string;
    interval: number;
    initial: T;
    render: (data: T) => ReactNode;
    headerLink?: ReactNode;
    className?: string;
    /** Called with each refreshed payload, for page content outside the panel that depends on it. */
    onData?: (data: T) => void;
}) {
    const timeZone = useServerTimezone();
    const [data, setData] = useState<T>(initial);
    const [state, setState] = useState<LiveState>('live');
    const [last, setLast] = useState(() => Date.now());
    const [now, setNow] = useState(() => Date.now());
    const [announce, setAnnounce] = useState('');
    const panel = useRef<HTMLElement>(null);
    const failures = useRef(0);
    const busy = useRef(false);
    const timer = useRef<number>(0);
    const stateRef = useRef<LiveState>('live');
    const every = Math.max(10, interval) * 1000;

    useEffect(() => setData(initial), [initial]);

    const change = (next: LiveState) => {
        const previous = stateRef.current;
        if (previous === next) return;
        stateRef.current = next;
        setState(next);
        if (next === 'error') setAnnounce('Live update failed. Showing older data.');
        if (next === 'expired') setAnnounce('Your session expired. Reload the page to sign in again.');
        if (previous === 'error' && next === 'live') setAnnounce('Live updates resumed.');
    };

    const refresh = async (manual: boolean) => {
        const node = panel.current;
        if (!node || stateRef.current === 'expired' || busy.current) return;
        const paused = document.hidden || document.querySelector('dialog[open]') !== null || node.matches(':hover') || node.contains(document.activeElement);
        if (!manual && paused) {
            change('paused');
            schedule(2000);
            return;
        }
        busy.current = true;
        node.setAttribute('aria-busy', 'true');
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), 10000);
        try {
            const response = await fetch(url, {
                credentials: 'same-origin',
                cache: 'no-store',
                headers: { Accept: 'application/json', 'X-Live-Fragment': '1' },
                signal: controller.signal,
            });
            if (response.status === 401 || (response.redirected && new URL(response.url).pathname.startsWith('/login'))) {
                change('expired');
                return;
            }
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const next = (await response.json()) as T;
            setData(next);
            onData?.(next);
            setLast(Date.now());
            failures.current = 0;
            change('live');
        } catch {
            failures.current += 1;
            change('error');
        } finally {
            window.clearTimeout(timeout);
            busy.current = false;
            node.removeAttribute('aria-busy');
            if ((stateRef.current as LiveState) !== 'expired') schedule(Math.min(every * 2 ** failures.current, 300000));
        }
    };

    const schedule = (delay: number) => {
        window.clearTimeout(timer.current);
        timer.current = window.setTimeout(() => void refresh(false), delay);
    };

    useEffect(() => {
        schedule(every);
        const tick = window.setInterval(() => setNow(Date.now()), 1000);
        const onVisible = () => {
            if (!document.hidden && Date.now() - last > every) void refresh(false);
        };
        document.addEventListener('visibilitychange', onVisible);
        return () => {
            window.clearTimeout(timer.current);
            window.clearInterval(tick);
            document.removeEventListener('visibilitychange', onVisible);
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [url, every]);

    const age = now - last;
    const when = `${clock(last, timeZone)} (${ago(age)})`;
    const stamp = {
        live: `Updated ${when}`,
        paused: `Paused · updated ${when}`,
        error: `Update failed · data from ${when}`,
        expired: 'Session expired · reload to sign in',
    }[state];
    const id = `${slugKey(title)}-title`;

    return (
        <section
            ref={panel}
            className={`panel live-panel ${className}${state !== 'expired' && age > every * 2.5 ? ' is-stale' : ''}`.trim()}
            data-live-state={state}
            aria-labelledby={id}
        >
            <div className="live-head">
                <h2 id={id}>{title}</h2>
                <div className="live-meta">
                    {headerLink}
                    <span className="live-dot" aria-hidden="true" />
                    <span>{stamp}</span>
                    <button type="button" className="link" onClick={() => void refresh(true)}>Refresh</button>
                </div>
            </div>
            <span className="sr-only" aria-live="polite">{announce}</span>
            <div className="live-body">{render(data)}</div>
        </section>
    );
}
