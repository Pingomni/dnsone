import { Link } from '@inertiajs/react';
import Icon from './Icon';

/** Key-figure card (legacy dashboardMetric); built server-side by App\Http\Support\Present::metric. */
export type Metric = { label: string; value: string; icon: string; tone: string; href: string };

export function MetricCard({ metric }: { metric: Metric }) {
    const body = (
        <div className={`metric dashboard-metric ${metric.tone}`.trim()}>
            <span className="metric-icon"><Icon name={metric.icon} className="metric-svg" /></span>
            <div><span>{metric.label}</span><strong>{metric.value}</strong></div>
        </div>
    );
    return metric.href ? <Link className="metric-link" href={metric.href}>{body}</Link> : body;
}

export function MetricCards({ metrics }: { metrics: Metric[] }) {
    return (
        <section className="cards dashboard-cards">
            {metrics.map((m) => <MetricCard key={m.label} metric={m} />)}
        </section>
    );
}
