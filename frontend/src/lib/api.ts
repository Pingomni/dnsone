import { useCallback, useEffect, useRef, useState } from 'react';
import { router } from '@inertiajs/react';

/** Error from the API: {"message", "errors": {field: message}}. */
export class ApiError extends Error {
    status: number;
    errors: Record<string, string>;
    constructor(status: number, message: string, errors: Record<string, string> = {}) {
        super(message);
        this.status = status;
        this.errors = errors;
    }
}

let csrf = '';
let onExpired: () => void = () => undefined;

export function setCsrf(token: string): void {
    csrf = token;
}

export function onSessionExpired(callback: () => void): void {
    onExpired = callback;
}

export async function api<T = unknown>(method: string, url: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (method !== 'GET') headers['X-CSRF-Token'] = csrf;
    let response: Response;
    try {
        response = await fetch(url, { method, headers, credentials: 'same-origin', cache: 'no-store', body: body === undefined ? undefined : JSON.stringify(body) });
    } catch {
        throw new ApiError(0, 'The server could not be reached. Check your connection and try again.');
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
        if (response.status === 401 && !url.startsWith('/api/auth/login')) onExpired();
        throw new ApiError(response.status, data.message ?? `Request failed (HTTP ${response.status}).`, data.errors ?? {});
    }
    return data as T;
}

export const get = <T,>(url: string) => api<T>('GET', url);
export const post = <T,>(url: string, body?: unknown) => api<T>('POST', url, body ?? {});
export const patch = <T,>(url: string, body: unknown) => api<T>('PATCH', url, body);
export const put = <T,>(url: string, body: unknown) => api<T>('PUT', url, body);
export const del = <T,>(url: string) => api<T>('DELETE', url);

/** GET a URL, refetching when it changes or when router.reload() is called. Keeps the last data while loading. */
export function useApi<T>(url: string | null) {
    const [data, setData] = useState<T | null>(null);
    const [error, setError] = useState<ApiError | null>(null);
    const [loading, setLoading] = useState(Boolean(url));
    const latest = useRef(0);

    const load = useCallback(async () => {
        if (!url) return;
        const id = ++latest.current;
        setLoading(true);
        try {
            const next = await get<T>(url);
            if (id === latest.current) {
                setData(next);
                setError(null);
            }
        } catch (e) {
            if (id === latest.current) setError(e as ApiError);
        } finally {
            if (id === latest.current) setLoading(false);
        }
    }, [url]);

    useEffect(() => {
        void load();
    }, [load]);
    useEffect(() => router.on('reload', () => void load()), [load]);

    return { data, setData, error, loading, reload: load };
}

/** The current page's query string (from the router, so it updates on navigation). */
export function searchOf(url: string): URLSearchParams {
    return new URLSearchParams(url.split('?')[1] ?? '');
}
