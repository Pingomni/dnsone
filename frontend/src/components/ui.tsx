import { useId, type ReactNode, type InputHTMLAttributes, type SelectHTMLAttributes, type TextareaHTMLAttributes } from 'react';
import { connectionLabel } from '@/lib/format';
import type { Flash, Option } from '@/lib/types';

// Building blocks with the legacy portal's markup and class names (styled by resources/css/app.css).

export function Panel({ title, children, className = '', actions }: { title?: string; children: ReactNode; className?: string; actions?: ReactNode }) {
    return (
        <section className={`panel ${className}`.trim()}>
            {title && (actions ? (
                <div className="panel-head"><h2>{title}</h2><div className="panel-actions">{actions}</div></div>
            ) : <h2>{title}</h2>)}
            {children}
        </section>
    );
}

export function ListPanel({ title, description, tools, children }: { title: string; description?: string; tools?: ReactNode; children: ReactNode }) {
    return (
        <section className="panel list-panel">
            <div className="list-panel-head">
                <div>
                    <h2>{title}</h2>
                    {description && <p>{description}</p>}
                </div>
                <div className="list-panel-tools">{tools}</div>
            </div>
            {children}
        </section>
    );
}

export function Badge({ children, tone = '' }: { children: ReactNode; tone?: string }) {
    return <span className={`badge ${tone}`.trim()}>{children}</span>;
}

/** Online is the normal case: plain text. Anything else is worth a look. */
export function ConnectionState({ state }: { state: string }) {
    return state === 'fresh accounting' ? <>{connectionLabel(state)}</> : <Badge tone="warning">{connectionLabel(state)}</Badge>;
}

/** Database timestamp, with the display timezone in a tooltip. */
export function Time({ value, timezone }: { value?: string | null; timezone?: string }) {
    if (!value || value === '-') return <>-</>;
    const text = value.slice(0, 19);
    return <time className="mono" dateTime={text.replace(' ', 'T')} title={timezone}>{text}</time>;
}

export function FlashMessage({ flash }: { flash: Flash }) {
    // Full-page errors are read on focus; success is announced by the layout's live region.
    const focus = flash.type === 'danger' || flash.type === 'warning';
    return (
        <div
            id="page-feedback"
            className={`flash ${flash.type}`}
            tabIndex={focus ? -1 : undefined}
            role={focus ? 'group' : undefined}
            aria-label={focus ? `${flash.type === 'danger' ? 'Error: ' : 'Warning: '}${flash.message}` : undefined}
            data-feedback-focus={focus ? '' : undefined}
        >
            {flash.message}
        </div>
    );
}

export function Empty({ children, tone = '' }: { children: ReactNode; tone?: string }) {
    return <div className={`empty ${tone}`.trim()}>{children}</div>;
}

export function HealthItem({ label, value, tone = '' }: { label: string; value: ReactNode; tone?: string }) {
    return (
        <div className="health-item">
            <span>{label}</span>
            <strong>{tone ? <Badge tone={tone}>{value}</Badge> : value}</strong>
        </div>
    );
}

type Described = { label: string; hint?: string; error?: string; className?: string };

function useDescribed(name: string | undefined, hint?: string, error?: string, id?: string) {
    const generated = useId();
    const fieldId = id ?? `field-${(name ?? 'f').replace(/[^a-zA-Z0-9_-]+/g, '-')}-${generated.replace(/:/g, '')}`;
    const described = [hint ? `${fieldId}-help` : '', error ? `${fieldId}-error` : ''].filter(Boolean).join(' ') || undefined;
    const notes = (
        <>
            {hint && <small id={`${fieldId}-help`}>{hint}</small>}
            {error && <small id={`${fieldId}-error`} className="field-error">{error}</small>}
        </>
    );
    return { fieldId, described, notes };
}

export function Field({ label, hint, error, className, ...input }: Described & InputHTMLAttributes<HTMLInputElement>) {
    const { fieldId, described, notes } = useDescribed(input.name, hint, error, input.id);
    return (
        <label htmlFor={fieldId} className={className}>
            <span id={`${fieldId}-label`}>{label}</span>
            <input type="text" {...input} id={fieldId} aria-describedby={described} aria-invalid={error ? true : undefined} />
            {notes}
        </label>
    );
}

export function TextArea({ label, hint, error, className = 'span2', ...input }: Described & TextareaHTMLAttributes<HTMLTextAreaElement>) {
    const { fieldId, described, notes } = useDescribed(input.name, hint, error, input.id);
    return (
        <label htmlFor={fieldId} className={className}>
            <span id={`${fieldId}-label`}>{label}</span>
            <textarea {...input} id={fieldId} aria-describedby={described} aria-invalid={error ? true : undefined} />
            {notes}
        </label>
    );
}

export function Select({ label, hint, error, className, options, placeholder, ...input }: Described & SelectHTMLAttributes<HTMLSelectElement> & { options: Option[] | Record<string, string>; placeholder?: string }) {
    const { fieldId, described, notes } = useDescribed(input.name, hint, error, input.id);
    const list: Option[] = Array.isArray(options) ? options : Object.entries(options).map(([value, text]) => ({ value, label: text }));
    const value = input.value === undefined || input.value === null ? undefined : String(input.value);
    const missing = value !== undefined && value !== '' && !list.some((o) => o.value === value);
    return (
        <label htmlFor={fieldId} className={className}>
            <span id={`${fieldId}-label`}>{label}</span>
            <select {...input} value={value} id={fieldId} aria-describedby={described} aria-invalid={error ? true : undefined}>
                {placeholder !== undefined && <option value="">{placeholder}</option>}
                {missing && <option value={value}>{value} (unavailable; choose again)</option>}
                {list.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
            {notes}
        </label>
    );
}

export function Check({ label, className = 'check', ...input }: { label: ReactNode; className?: string } & InputHTMLAttributes<HTMLInputElement>) {
    return (
        <label className={className}>
            <input type="checkbox" {...input} /> {label}
        </label>
    );
}

export function FormActions({ children, className = 'span2 form-actions' }: { children: ReactNode; className?: string }) {
    return <div className={className}>{children}</div>;
}

/** Error summary at the top of a form; links move focus to the field. */
export function ErrorSummary({ errors }: { errors: Record<string, string | undefined> }) {
    const entries = Object.entries(errors).filter(([, message]) => message);
    if (!entries.length) return null;
    return (
        <section id="form-error-summary" className="flash danger error-summary" tabIndex={-1} role="group" aria-labelledby="form-error-title" data-error-summary="">
            <h2 id="form-error-title">There is a problem</h2>
            <ul>
                {entries.map(([name, message]) => (
                    <li key={name}>
                        <a
                            href={`#${name}`}
                            onClick={(event) => {
                                const field = document.querySelector<HTMLElement>(`[name="${CSS.escape(name)}"]`);
                                if (!field) return;
                                event.preventDefault();
                                field.focus();
                                field.scrollIntoView({ block: 'center' });
                            }}
                        >
                            {message}
                        </a>
                    </li>
                ))}
            </ul>
        </section>
    );
}

/** A <details> menu that closes on outside click and Escape (legacy .list-menu). */
export function ListMenu({ summary, label, className = 'list-menu', children }: { summary: ReactNode; label?: string; className?: string; children: ReactNode }) {
    return (
        <details
            className={className}
            onKeyDown={(event) => {
                if (event.key !== 'Escape') return;
                const details = event.currentTarget;
                details.open = false;
                details.querySelector('summary')?.focus();
                event.preventDefault();
            }}
            ref={(details) => {
                if (!details) return;
                const close = (event: MouseEvent) => {
                    if (details.open && !details.contains(event.target as Node)) details.open = false;
                };
                document.addEventListener('click', close);
                return () => document.removeEventListener('click', close);
            }}
        >
            <summary className="button" aria-label={label}>{summary}</summary>
            {children}
        </details>
    );
}

export function RowActions({ label, children }: { label: string; children: ReactNode }) {
    return (
        <ListMenu summary="More" label={label} className="list-menu list-row-menu">
            <div className="list-row-options">{children}</div>
        </ListMenu>
    );
}

export interface TagData {
    text: string;
    tone?: string | null;
    title?: string;
    href?: string;
}

/** Server-built status tag (App\Http\Support\Present::tag): plain text when tone is null, else a badge. */
export function Tag({ tag }: { tag: TagData }) {
    if (tag.tone === null || tag.tone === undefined) return <span title={tag.title}>{tag.text}</span>;
    const badge = <span className={`badge ${tag.tone}`.trim()} title={tag.title}>{tag.text}</span>;
    return tag.href ? <a className="badge-link" href={tag.href} aria-label={`${tag.text}, open`}>{badge}</a> : badge;
}

export function Tags({ tags }: { tags: TagData[] }) {
    return <>{tags.map((tag, i) => <Tag key={i} tag={tag} />)}</>;
}
