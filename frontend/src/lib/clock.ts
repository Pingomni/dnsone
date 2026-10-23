import { useEffect, useState } from 'react';
import { useShared } from './auth';

// The portal shows every time in the server's clock and timezone (the same ones RADIUS, accounting
// and the server-formatted tables use), not the browser's: an operator abroad, or a PC whose clock
// is off, still sees times that line up with the logs.

let offset = 0;

/** Called with the server's epoch seconds from each page load; keeps how far the browser clock is off. */
export function syncServerClock(serverSeconds: number): void {
    if (serverSeconds > 0) offset = serverSeconds * 1000 - Date.now();
}

/** Current server time in milliseconds. */
export function serverNow(): number {
    return Date.now() + offset;
}

/** Converts a browser timestamp (Date.now()) to server time. */
export function toServerTime(browserMs: number): number {
    return browserMs + offset;
}

/** Formats an instant in the server's timezone; falls back to the browser's if the zone is unknown. */
export function formatInZone(ms: number, timeZone: string, options: Intl.DateTimeFormatOptions): string {
    try {
        return new Date(ms).toLocaleString('en-GB', { ...options, timeZone });
    } catch {
        return new Date(ms).toLocaleString('en-GB', options);
    }
}

/** The server timezone from the shared props. */
export function useServerTimezone(): string {
    return useShared().clock.timezone;
}

/** Server time as HH:MM, ticking at each minute change. */
export function useServerClock(): string {
    const { clock } = useShared();
    syncServerClock(clock.now);
    const format = () => formatInZone(serverNow(), clock.timezone, { hour: '2-digit', minute: '2-digit', hour12: false });
    const [time, setTime] = useState(format);
    useEffect(() => {
        let timer = 0;
        const tick = () => {
            setTime(format());
            timer = window.setTimeout(tick, 60_000 - (serverNow() % 60_000) + 50);
        };
        tick();
        return () => window.clearTimeout(timer);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [clock.now, clock.timezone]);
    return time;
}
