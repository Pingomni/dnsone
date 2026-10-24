/**
 * Scrolling in the console (DNSOne's own; RadiusOne's components are left unchanged):
 * - Back and Forward return to where the page was scrolled. Pages load their data after they render,
 *   so the browser's own restoration finds a short page and gives up; this waits for the content.
 * - Switching tabs keeps the position (the page does not collapse while the new tab loads), and brings
 *   the tab strip into view if it was scrolled past.
 * - Paging through a list (First, Previous, Next, Last, Older) shows the top of that list.
 * - The phone menu holds the page still behind it.
 */

const KEY = 'dnsone.scroll';
const RESTORE_MS = 2500;
const HOLD_QUIET_MS = 150;
const HOLD_MAX_MS = 2000;

type Positions = Record<string, number>;

function load(): Positions {
    try {
        return JSON.parse(sessionStorage.getItem(KEY) ?? '{}') as Positions;
    } catch {
        return {};
    }
}

let positions: Positions = load();
let current = '';

function save(): void {
    try {
        sessionStorage.setItem(KEY, JSON.stringify(positions));
    } catch { /* private mode: positions last for this page load only */ }
}

function newKey(): string {
    return Math.random().toString(36).slice(2, 10);
}

/** Gives the current history entry a key; called once at start. */
export function initScroll(): void {
    if ('scrollRestoration' in window.history) window.history.scrollRestoration = 'manual';
    const state = window.history.state as { scrollKey?: string } | null;
    current = state?.scrollKey ?? newKey();
    if (!state?.scrollKey) window.history.replaceState({ ...(state ?? {}), scrollKey: current }, '');
    let pending = 0;
    window.addEventListener('scroll', () => {
        if (pending) return;
        pending = window.requestAnimationFrame(() => {
            pending = 0;
            positions[current] = Math.round(window.scrollY);
        });
    }, { passive: true });
    window.addEventListener('pagehide', save);
    if (positions[current]) restore(positions[current]);
}

/** Before pushState: remembers this entry's position and returns the state for the new entry. */
export function leaving(): { scrollKey: string } {
    positions[current] = Math.round(window.scrollY);
    current = newKey();
    save();
    return { scrollKey: current };
}

/** After popstate: back to the position this entry had. */
export function arrived(): void {
    positions[current] = Math.round(window.scrollY);
    const state = window.history.state as { scrollKey?: string } | null;
    current = state?.scrollKey ?? newKey();
    save();
    restore(positions[current] ?? 0);
}

/** Scrolls to y as soon as the page is tall enough; stops if the person scrolls first. */
function restore(y: number): void {
    const until = performance.now() + RESTORE_MS;
    let stopped = false;
    const stop = () => { stopped = true; };
    const events = ['wheel', 'touchstart', 'keydown', 'mousedown'] as const;
    events.forEach((e) => window.addEventListener(e, stop, { once: true, passive: true }));
    const step = () => {
        if (stopped) return;
        const max = document.documentElement.scrollHeight - window.innerHeight;
        window.scrollTo(0, Math.min(y, Math.max(0, max)));
        if (max >= y || performance.now() > until) {
            events.forEach((e) => window.removeEventListener(e, stop));
            return;
        }
        window.requestAnimationFrame(step);
    };
    window.requestAnimationFrame(step);
}

function topbarHeight(): number {
    return document.querySelector<HTMLElement>('.topbar')?.getBoundingClientRect().height ?? 0;
}

/** Scrolls so `element` starts just below the sticky top bar, if it is above that. */
function reveal(element: Element | null): void {
    if (!element) return;
    const top = element.getBoundingClientRect().top - topbarHeight() - 8;
    if (top < 0) window.scrollBy(0, top);
}

let releaseHold: (() => void) | null = null;

/**
 * Keeps the page from collapsing while a newly shown tab or list page loads: the height is held until
 * the page has stopped changing for a moment (its data arrived), or for HOLD_MAX_MS at most.
 */
function holdHeight(): void {
    releaseHold?.();
    const root = document.documentElement;
    root.style.minHeight = `${root.scrollHeight}px`;
    let quiet = 0;
    const release = () => {
        observer.disconnect();
        window.clearTimeout(quiet);
        window.clearTimeout(limit);
        root.style.minHeight = '';
        releaseHold = null;
    };
    const observer = new MutationObserver(() => {
        window.clearTimeout(quiet);
        quiet = window.setTimeout(release, HOLD_QUIET_MS);
    });
    observer.observe(document.querySelector('.main') ?? document.body, { childList: true, subtree: true, characterData: true });
    quiet = window.setTimeout(release, HOLD_QUIET_MS * 2);
    const limit = window.setTimeout(release, HOLD_MAX_MS);
    releaseHold = release;
}

/** Tabs and list paging, for every page: one listener on the document. Returns the cleanup. */
export function watchClicks(): () => void {
    const onClick = (event: MouseEvent) => {
        const target = event.target as Element | null;
        const tab = target?.closest('[role="tab"]');
        if (tab) {
            holdHeight();
            reveal(tab.closest('[role="tablist"]'));
            return;
        }
        const pager = target?.closest('.server-pagination a, a[data-list-page]');
        if (pager && !event.defaultPrevented && event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey) {
            holdHeight();
            const list = pager.closest('.list-panel, .panel, .settings-sheet, section') ?? pager.parentElement;
            // After the router has moved (preserveScroll keeps the position), bring the list's top into view.
            window.setTimeout(() => reveal(list), 0);
        }
    };
    // Arrow keys, Home and End switch tabs too.
    const onKey = (event: KeyboardEvent) => {
        if ((event.target as Element | null)?.closest('[role="tab"]') && ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) holdHeight();
    };
    // Capture: React re-renders inside its own handler, before the event would reach the document.
    document.addEventListener('click', onClick, true);
    document.addEventListener('keydown', onKey, true);
    return () => {
        document.removeEventListener('click', onClick, true);
        document.removeEventListener('keydown', onKey, true);
    };
}

/** Holds the page still while the phone menu is open. */
export function lockPage(locked: boolean): void {
    document.documentElement.classList.toggle('page-locked', locked);
}
