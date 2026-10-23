import { useEffect, useRef, useState, type ReactNode } from 'react';
import Icon from './Icon';

export interface TabDef {
    key: string;
    title: string;
    icon?: string;
    count?: number;
    hint?: string;
    content: ReactNode;
    /** Rendered even when hidden (forms whose fields must submit from every tab). */
    keepMounted?: boolean;
}

/** Scrolls a horizontal tab strip so its current item is in view (phones show only part of the strip). */
export function revealCurrent(list: HTMLElement | null): void {
    const item = list?.querySelector<HTMLElement>('[aria-selected="true"], [aria-current="page"], [aria-current="true"]');
    if (!list || !item || list.scrollWidth <= list.clientWidth) return;
    const box = list.getBoundingClientRect();
    const at = item.getBoundingClientRect();
    list.scrollLeft += at.left + at.width / 2 - (box.left + box.width / 2);
}

function requestedTab(param: string): string | null {
    return new URL(window.location.href).searchParams.get(param);
}

/**
 * Accessible tabs (legacy .tabs): arrow keys / Home / End move between tabs, the selected tab is
 * kept in ?tab= so reload and Back restore it, and a native "invalid" event inside a hidden panel
 * reveals that panel first.
 */
export function Tabs({ tabs, defaultTab, label, className = 'tabs', listClassName = 'tab-buttons', vertical = false, param = 'tab', onChange }: {
    tabs: TabDef[];
    defaultTab?: string;
    label: string;
    className?: string;
    listClassName?: string;
    vertical?: boolean;
    param?: string;
    onChange?: (key: string) => void;
}) {
    const fallback = defaultTab ?? tabs[0]?.key;
    const pick = (requested: string | null) => (tabs.some((t) => t.key === requested) ? (requested as string) : fallback);
    const [active, setActive] = useState<string>(() => pick(typeof window === 'undefined' ? null : requestedTab(param)));
    const buttons = useRef<Record<string, HTMLButtonElement | null>>({});
    const root = useRef<HTMLElement>(null);
    const list = useRef<HTMLDivElement>(null);

    const select = (key: string, focus = false, push = true) => {
        setActive(key);
        onChange?.(key);
        if (push) {
            const url = new URL(window.location.href);
            url.searchParams.set(param, key);
            if (url.href !== window.location.href) window.history.replaceState(window.history.state, '', url);
        }
        if (focus) buttons.current[key]?.focus({ preventScroll: true });
    };

    useEffect(() => revealCurrent(list.current), [active]);

    useEffect(() => {
        const onPop = () => setActive(pick(requestedTab(param)));
        window.addEventListener('popstate', onPop);
        return () => window.removeEventListener('popstate', onPop);
    });

    useEffect(() => {
        const node = root.current;
        if (!node) return;
        const onInvalid = (event: Event) => {
            const panel = (event.target as HTMLElement).closest<HTMLElement>('[role="tabpanel"]');
            const key = panel?.dataset.tabKey;
            if (key && panel?.closest('[data-tabs-root]') === node && panel.hidden) select(key, false, true);
        };
        node.addEventListener('invalid', onInvalid, true);
        return () => node.removeEventListener('invalid', onInvalid, true);
    });

    const onKeyDown = (event: React.KeyboardEvent, index: number) => {
        if (event.altKey || event.ctrlKey || event.metaKey) return;
        const next: Record<string, number> = {
            [vertical ? 'ArrowDown' : 'ArrowRight']: (index + 1) % tabs.length,
            [vertical ? 'ArrowUp' : 'ArrowLeft']: (index + tabs.length - 1) % tabs.length,
            Home: 0,
            End: tabs.length - 1,
        };
        if (!(event.key in next)) return;
        event.preventDefault();
        select(tabs[next[event.key]].key, true);
    };

    return (
        <section className={className} ref={root} data-tabs-root="">
            <div className={listClassName} role="tablist" aria-label={label} aria-orientation={vertical ? 'vertical' : undefined} ref={list}>
                {tabs.map((tab, index) => {
                    const selected = tab.key === active;
                    return (
                        <button
                            type="button"
                            role="tab"
                            key={tab.key}
                            ref={(el) => { buttons.current[tab.key] = el; }}
                            id={`tab-button-${tab.key}`}
                            aria-controls={`tab-${tab.key}`}
                            aria-selected={selected}
                            tabIndex={selected ? 0 : -1}
                            className={selected ? 'active' : undefined}
                            title={tab.hint}
                            onClick={() => select(tab.key, true)}
                            onKeyDown={(event) => onKeyDown(event, index)}
                        >
                            {tab.icon && <Icon name={tab.icon} />}
                            {tab.title}
                            {tab.count !== undefined && <span className="tab-count">{tab.count}</span>}
                        </button>
                    );
                })}
            </div>
            {tabs.map((tab) => {
                const selected = tab.key === active;
                if (!selected && !tab.keepMounted) return null;
                return (
                    <div
                        key={tab.key}
                        className={`tab${selected ? ' active' : ''}`}
                        id={`tab-${tab.key}`}
                        role="tabpanel"
                        aria-labelledby={`tab-button-${tab.key}`}
                        tabIndex={0}
                        hidden={!selected}
                        data-tab-key={tab.key}
                    >
                        {tab.content}
                    </div>
                );
            })}
        </section>
    );
}
