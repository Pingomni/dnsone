import { Link } from '@inertiajs/react';
import { useMemo, useRef, useState, type ReactNode } from 'react';
import type { Paginated } from '@/lib/types';

export interface Column<T> {
    /** Header text; also the mobile card label. */
    header: ReactNode;
    /** Cell content. */
    cell: (row: T, index: number) => ReactNode;
    /** Excluded from "export loaded rows" (actions, checkboxes). */
    noExport?: boolean;
    className?: string;
}

type TableProps<T> = {
    columns: Column<T>[];
    rows: T[];
    rowKey?: (row: T, index: number) => string | number;
    /** Show the "Export loaded rows CSV" tool. */
    exportRows?: boolean;
    /** Rows are one server page: no client paging; export says "current page". */
    serverPaginated?: boolean;
    resetHref?: string;
    emptyText?: ReactNode;
    perPage?: number;
};

function textOf(node: ReactNode): string {
    if (node === null || node === undefined || typeof node === 'boolean') return '';
    if (typeof node === 'string' || typeof node === 'number') return String(node);
    return '';
}

/**
 * Data table with the legacy behaviour: data-label per cell for the mobile card layout,
 * client-side pages of 30 for unpaginated lists, and CSV export of what is on screen.
 */
export function DataTable<T>({ columns, rows, rowKey, exportRows = false, serverPaginated = false, resetHref, emptyText = 'No records found.', perPage = 30 }: TableProps<T>) {
    const [page, setPage] = useState(1);
    const tableRef = useRef<HTMLTableElement>(null);
    const paged = !serverPaginated && rows.length > perPage;
    const pageCount = paged ? Math.ceil(rows.length / perPage) : 1;
    const current = Math.min(page, pageCount);
    const visible = useMemo(() => (paged ? rows.slice((current - 1) * perPage, current * perPage) : rows), [rows, paged, current, perPage]);

    const exportCsv = () => {
        const table = tableRef.current;
        if (!table) return;
        const keep = columns.map((c, i) => (c.noExport ? -1 : i)).filter((i) => i >= 0);
        const cell = (value: string) => {
            const safe = /^[=+@\-\t\r]/.test(value) ? `'${value}` : value;
            return `"${safe.replaceAll('"', '""')}"`;
        };
        const lines = [...table.querySelectorAll('tr')]
            .filter((tr) => !tr.querySelector('.empty'))
            .map((tr) => keep.map((i) => cell(tr.children[i]?.textContent?.trim() ?? '')).join(','));
        const blob = new Blob([lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = serverPaginated ? 'export-current-page.csv' : 'export-loaded-rows.csv';
        link.click();
        URL.revokeObjectURL(link.href);
    };

    return (
        <>
            {exportRows && (
                <div className={`table-tools${serverPaginated ? ' list-export-tools' : ''}`}>
                    <button type="button" onClick={exportCsv} disabled={!rows.length}>
                        Export {serverPaginated ? 'current page' : 'loaded rows'} CSV
                    </button>
                </div>
            )}
            <div className="table-wrap">
                <table ref={tableRef}>
                    <thead>
                        <tr>
                            {columns.map((c, i) => <th scope="col" key={i} className={c.className}>{c.header}</th>)}
                        </tr>
                    </thead>
                    <tbody>
                        {!rows.length && (
                            <tr>
                                <td colSpan={columns.length} className="empty">
                                    {emptyText}
                                    {resetHref && <> <Link className="button" href={resetHref}>Reset filters</Link></>}
                                </td>
                            </tr>
                        )}
                        {visible.map((row, index) => (
                            <tr key={rowKey ? rowKey(row, index) : index}>
                                {columns.map((c, i) => {
                                    const content = c.cell(row, index);
                                    const plain = textOf(content);
                                    const empty = content === null || content === undefined || content === '' || plain === '-';
                                    return (
                                        <td key={i} className={[c.className, empty ? 'is-empty' : ''].filter(Boolean).join(' ') || undefined} data-label={textOf(c.header)}>
                                            {empty && content !== '-' ? '-' : content}
                                        </td>
                                    );
                                })}
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
            {paged && (
                <div className="pagination" role="navigation" aria-label="Table pagination">
                    {Array.from({ length: pageCount }, (_, i) => i + 1).map((p) => (
                        <button type="button" key={p} className={p === current ? 'active' : undefined} aria-current={p === current ? 'page' : undefined} onClick={() => setPage(p)}>
                            {p}
                        </button>
                    ))}
                </div>
            )}
        </>
    );
}

/** Server pagination bar (legacy listPagination). `query` holds the active filters. */
export function Pagination<T>({ result, path, query, noun }: { result: Paginated<T>; path: string; query: Record<string, string | number | undefined>; noun: string }) {
    const first = result.total ? (result.page - 1) * result.size + 1 : 0;
    const last = Math.min(result.page * result.size, result.total);
    const href = (page: number) => {
        const params = new URLSearchParams();
        Object.entries(query).forEach(([k, v]) => {
            if (v !== undefined && v !== '' && k !== 'page') params.set(k, String(v));
        });
        params.set('page', String(page));
        return `${path}?${params.toString()}`;
    };
    const label = result.total === 1 ? noun.replace(/s$/, '') : noun;
    const links: [string, number, boolean][] = [
        ['First', 1, result.page <= 1],
        ['Previous', result.page - 1, result.page <= 1],
        ['Next', result.page + 1, result.page >= result.pages],
        ['Last', result.pages, result.page >= result.pages],
    ];
    return (
        <nav className="pagination server-pagination" aria-label={`${noun[0].toUpperCase()}${noun.slice(1)} pages`}>
            <span className="pagination-summary">
                Showing {first}–{last} of {result.total} {label}
                {result.pages > 1 ? `; page ${result.page} of ${result.pages}` : ''}
            </span>
            {result.pages > 1 && links.map(([text, page, disabled]) => disabled
                ? <button type="button" key={text} disabled>{text}</button>
                : <Link key={text} className="button" href={href(page)} preserveScroll>{text}</Link>)}
        </nav>
    );
}

/** "Export CSV" menu: current page (client-side) or every match (server streams /…/export). */
export function ExportMenu({ url, total, loaded, onExportPage }: { url: string; total: number; loaded: number; onExportPage?: () => void }) {
    return (
        <details className="list-menu list-export-menu">
            <summary className="button">Export CSV</summary>
            <div className="list-menu-options">
                <button
                    type="button"
                    disabled={!loaded}
                    onClick={() => {
                        if (onExportPage) return onExportPage();
                        document.querySelector<HTMLButtonElement>('.list-export-tools button')?.click();
                    }}
                >
                    Export current page CSV<span className="list-subline">{loaded} rows on this page</span>
                </button>
                <a href={url}>
                    Export all matches CSV ({total})<span className="list-subline">Every record matching these filters</span>
                </a>
            </div>
        </details>
    );
}
