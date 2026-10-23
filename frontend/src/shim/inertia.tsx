/**
 * Stand-in for @inertiajs/react, so RadiusOne's components (Link, router, usePage, Head) run unchanged
 * in a plain SPA. Navigation uses the History API; page data comes from the REST API (lib/api.ts), and
 * usePage().props carries the shared props RadiusOne expects (operator, permissions, clock, app name).
 */
import { createContext, useContext, useEffect, type AnchorHTMLAttributes, type MouseEvent, type ReactNode } from 'react';
import type { SharedProps } from '@/lib/types';

export type Page = { component: string; props: SharedProps; url: string };
type Options = { preserveScroll?: boolean; preserveState?: boolean; replace?: boolean; onFinish?: () => void; onSuccess?: () => void; onStart?: () => void; data?: Record<string, unknown> };

const PageContext = createContext<Page | null>(null);
type Listener = (event: string) => void;
const listeners = new Set<Listener>();
let navigateTo: (url: string, options?: Options) => void = (url) => window.location.assign(url);
let writeTo: (method: string, url: string, data?: unknown) => Promise<void> = async () => undefined;

/** Wired up by src/main.tsx. */
export function bindRouter(navigate: typeof navigateTo, write: typeof writeTo): void {
    navigateTo = navigate;
    writeTo = write;
}

export function emit(event: string): void {
    listeners.forEach((listener) => listener(event));
}

export function PageProvider({ page, children }: { page: Page; children: ReactNode }) {
    return <PageContext.Provider value={page}>{children}</PageContext.Provider>;
}

export function withData(url: string, data?: Record<string, unknown>): string {
    if (!data || !Object.keys(data).length) return url;
    const [path, query = ''] = url.split('?');
    const params = new URLSearchParams(query);
    Object.entries(data).forEach(([k, v]) => {
        if (v === undefined || v === null || v === '') params.delete(k);
        else params.set(k, String(v));
    });
    const q = params.toString();
    return q ? `${path}?${q}` : path;
}

export function usePage<T = SharedProps>(): Page & { props: T } {
    const page = useContext(PageContext);
    if (!page) throw new Error('usePage outside PageProvider');
    return page as Page & { props: T };
}

export function Head({ title }: { title?: string; children?: ReactNode }) {
    useEffect(() => {
        if (title) document.title = title;
    }, [title]);
    return null;
}

type LinkProps = Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'href'> & {
    href: string;
    method?: string;
    as?: string;
    data?: Record<string, unknown>;
    preserveScroll?: boolean;
    preserveState?: boolean;
    replace?: boolean;
    only?: string[];
    prefetch?: boolean | string;
};

export function Link({ href, method, as: _as, data, preserveScroll, preserveState: _preserveState, replace, only: _only, prefetch: _prefetch, onClick, children, ...rest }: LinkProps) {
    const target = withData(href, method && method !== 'get' ? undefined : data);
    const click = (event: MouseEvent<HTMLAnchorElement>) => {
        onClick?.(event);
        if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) return;
        event.preventDefault();
        if (method && method.toLowerCase() !== 'get') {
            void writeTo(method.toUpperCase(), href, data);
            return;
        }
        navigateTo(target, { preserveScroll, replace });
    };
    return <a href={target} onClick={click} {...rest}>{children}</a>;
}

async function write(method: string, url: string, data: unknown, options: Options = {}) {
    options.onStart?.();
    try {
        await writeTo(method, url, data);
        options.onSuccess?.();
    } finally {
        options.onFinish?.();
    }
}

export const router = {
    get(url: string, data?: Record<string, unknown>, options: Options = {}) {
        navigateTo(withData(url, data), options);
    },
    visit(url: string, options: Options & { method?: string } = {}) {
        if (options.method && options.method !== 'get') void write(options.method.toUpperCase(), url, options.data, options);
        else navigateTo(withData(url, options.data), options);
    },
    post: (url: string, data?: unknown, options?: Options) => void write('POST', url, data, options),
    put: (url: string, data?: unknown, options?: Options) => void write('PUT', url, data, options),
    patch: (url: string, data?: unknown, options?: Options) => void write('PATCH', url, data, options),
    delete: (url: string, options?: Options) => void write('DELETE', url, undefined, options),
    /** Pages refetch their data on 'reload'. */
    reload(_options: Options = {}) {
        emit('reload');
    },
    on(event: string, callback: () => void) {
        const listener: Listener = (e) => {
            if (e === event) callback();
        };
        listeners.add(listener);
        return () => {
            listeners.delete(listener);
        };
    },
};
