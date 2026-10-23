"""dnsone-ctl: administration and the jobs the systemd timers run.

    dnsone-ctl migrate [--status]
    dnsone-ctl create-admin USERNAME [--name N] [--email E] [--role admin] [--reset-two-factor]
                                            (password from prompt or stdin)
    dnsone-ctl status                       service health; exit 1 on errors, 2 on warnings
    dnsone-ctl sync                         bring this node up to date with MySQL (dnsone-sync.timer)
    dnsone-ctl zones list
    dnsone-ctl zones publish NAME           validate + write + reload one zone now
    dnsone-ctl zones reconcile [--force]    publish everything behind MySQL (dnsone-reconcile.timer)
    dnsone-ctl rpz refresh                  download every blocklist, then rebuild (dnsone-rpz.timer)
    dnsone-ctl rpz build                    rebuild and reload the RPZ from what is stored
    dnsone-ctl rpz pause [--minutes N] [--group NAME]   pause blocking (0 minutes: until resumed)
    dnsone-ctl rpz resume [--group NAME]
    dnsone-ctl stats collect                store one statistics sample (dnsone-stats.timer)
    dnsone-ctl alerts check                 notify about problems (Settings → Alerts; dnsone-stats.timer)
    dnsone-ctl alerts test                  send a test alert to every channel that is on
    dnsone-ctl cluster nodes                the nodes sharing this database (Phase 2)
    dnsone-ctl cluster secondary-config --primary IP [--port 5301]   named.conf lines for a secondary
"""

from __future__ import annotations

import argparse
import getpass
import sys

from sqlalchemy import select

from . import alerts, cluster, health, logsetup, migrate, rpz, runtime, security, stats, validation
from .config import get_settings
from .db import get_engine, session_scope
from .models import ClientGroup, Role, User, Zone
from .zonegen import Publisher


def _migrate(args) -> int:
    engine = get_engine()
    if args.status:
        done = migrate.applied(engine)
        for path in migrate.available():
            print(f"{'applied' if path.stem in done else 'PENDING'}  {path.name}")
        return 0
    count = migrate.run(engine)
    print(f"{count} migration(s) applied" if count else "schema is up to date")
    return 0


def _create_admin(args) -> int:
    try:
        username = validation.username(args.username)
        email = validation.email(args.email or "")
    except validation.ValidationError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return 1
    if sys.stdin.isatty():
        password = getpass.getpass("Password (12+ characters): ")
        if getpass.getpass("Repeat password: ") != password:
            print("error: the passwords differ", file=sys.stderr)
            return 1
    else:
        password = sys.stdin.readline().rstrip("\n")
    try:
        validation.password(password)
    except validation.ValidationError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return 1
    with session_scope() as db:
        role = db.scalar(select(Role).where(Role.name == args.role))
        if role is None:
            print(f"error: no role named {args.role!r}; run `dnsone-ctl migrate` first", file=sys.stderr)
            return 1
        user = db.scalar(select(User).where(User.username == username))
        if user is None:
            db.add(User(username=username, name=args.name or username, email=email, role_id=role.id, password_hash=security.hash_password(password)))
            print(f"created {username} ({role.name})")
        else:
            user.password_hash = security.hash_password(password)
            user.role_id, user.enabled, user.locked_until, user.failed_logins = role.id, True, None, 0
            if args.reset_two_factor and user.totp_enabled:
                security.disable_two_factor(user)
                print(f"{username}: two-factor sign-in turned off")
            security.end_user_sessions(db, user.id)
            print(f"updated {username}: new password, role {role.name}, enabled")
    return 0


def _status(_args) -> int:
    with session_scope() as db:
        results = health.checks(db)
    width = max(len(r["name"]) for r in results)
    marks = {"ok": "OK  ", "warning": "WARN", "error": "FAIL"}
    for r in results:
        print(f"{marks[r['status']]}  {r['name']:<{width}}  {r['detail']}")
    overall = health.overall(results)
    print(f"\noverall: {overall}")
    return {"ok": 0, "error": 1, "warning": 2}[overall]


def _zones(args) -> int:
    publisher = Publisher()
    if args.action == "list":
        with session_scope() as db:
            for z in db.scalars(select(Zone).order_by(Zone.name)):
                print(f"{z.name:<40} {z.status:<9} {z.publish_state:<10} serial {z.published_serial or '-'}")
        return 0
    if args.action == "publish":
        with session_scope() as db:
            zone = db.scalar(select(Zone).where(Zone.name == args.name.lower().rstrip(".")))
            if zone is None:
                print(f"error: no zone {args.name}", file=sys.stderr)
                return 1
            zone_id = zone.id
        result = publisher.publish(zone_id, force=True)
        print(f"{'OK  ' if result.ok else 'FAIL'}  {result.zone}: {result.message}")
        return 0 if result.ok else 1
    results = publisher.reconcile(force=args.force)
    failed = [r for r in results if not r.ok]
    for r in results:
        if not r.skipped or not r.ok:
            print(f"{'OK  ' if r.ok else 'FAIL'}  {r.zone}: {r.message}")
    print(f"reconcile: {len(results)} zone(s) checked, {len(failed)} failed")
    return 1 if failed else 0


def _group_id(name: str | None) -> int | None:
    if not name:
        return None
    with session_scope() as db:
        group = db.scalar(select(ClientGroup).where(ClientGroup.name == name))
        if group is None:
            raise SystemExit(f"error: no group named {name!r}")
        return group.id


def _rpz(args) -> int:
    if args.action in ("pause", "resume"):
        group_id = _group_id(args.group)
        with session_scope() as db:
            if args.action == "pause":
                runtime.set_pause(db, group_id, args.minutes)
            else:
                runtime.resume(db, group_id)
        for m in runtime.apply():
            print(m)
        who = args.group or "everyone"
        print(f"blocking {'paused' if args.action == 'pause' else 'resumed'} for {who}"
              + (f" ({args.minutes} minutes)" if args.action == "pause" and args.minutes else " (until resumed)" if args.action == "pause" else ""))
        return 0
    if args.action == "refresh":
        for r in rpz.Blocklists().refresh_all():
            print(f"{r.status:<12} {r.name}: {r.message}")
    result = rpz.RpzBuilder().build()
    print(f"{'OK  ' if result.ok else 'FAIL'}  RPZ serial {result.serial}, {result.entries} triggers: {result.message}")
    return 0 if result.ok else 1


def _stats(_args) -> int:
    with session_scope() as db:
        sample = stats.collect(db)
        print(f"queries={sample.queries} blocked={sample.blocked} cache_hits={sample.cache_hits}")
    return 0


def _alerts(args) -> int:
    with session_scope() as db:
        if args.action == "test":
            results = alerts.send_test(db)
            for channel, result in results.items():
                print(f"{channel}: {result}")
            return 0 if all(r == "ok" for r in results.values()) else 1
        result = alerts.check(db)
    for a in result["active"]:
        print(f"{a['severity'].upper():<8} {a['title']}: {a['detail']} (since {a['since']})")
    if result["sent"] or result["resolved"]:
        print(f"notified: {len(result['sent'])} new, {len(result['resolved'])} resolved; {result['delivery']}")
    if not result["active"]:
        print("no problems")
    return 0


def _sync(_args) -> int:
    ok, messages = cluster.sync()
    for m in messages:
        print(m)
    print("sync: ok" if ok else "sync: finished with errors")
    return 0 if ok else 1


def _cluster(args) -> int:
    if args.action == "secondary-config":
        print(cluster.render_secondary_config(get_settings().catalog_zone, args.primary, args.port), end="")
        return 0
    with session_scope() as db:
        rows = cluster.nodes(db)
    for n in rows:
        rpz_state = n.get("rpz") or {}
        print(f"{n['node']:<20} {n['role']:<8} v{n['version']:<8} last sync {n['last_seen']}{'  (STALE)' if n['stale'] else ''}"
              f"  rpz {rpz_state.get('state')} serial {rpz_state.get('serial')}{'  (behind)' if n['rpz_behind'] else ''}")
    if not rows:
        print("no node has synced yet: run dnsone-ctl sync")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dnsone-ctl", description="DNSOne administration")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("migrate", help="apply database migrations")
    p.add_argument("--status", action="store_true")
    p.set_defaults(func=_migrate)

    p = sub.add_parser("create-admin", help="create an operator, or reset its password")
    p.add_argument("username")
    p.add_argument("--name", default="")
    p.add_argument("--email", default="")
    p.add_argument("--role", default="admin")
    p.add_argument("--reset-two-factor", action="store_true", help="turn off two-factor sign-in (lost phone)")
    p.set_defaults(func=_create_admin)

    p = sub.add_parser("sync", help="bring this node up to date with MySQL")
    p.set_defaults(func=_sync)

    p = sub.add_parser("status", help="health of every component")
    p.set_defaults(func=_status)

    p = sub.add_parser("zones", help="zone publishing")
    zsub = p.add_subparsers(dest="action", required=True)
    zsub.add_parser("list")
    zp = zsub.add_parser("publish")
    zp.add_argument("name")
    zr = zsub.add_parser("reconcile")
    zr.add_argument("--force", action="store_true", help="rewrite every zone, even if up to date")
    p.set_defaults(func=_zones)

    p = sub.add_parser("rpz", help="ad-blocking")
    rsub = p.add_subparsers(dest="action", required=True)
    rsub.add_parser("refresh")
    rsub.add_parser("build")
    rp = rsub.add_parser("pause")
    rp.add_argument("--minutes", type=int, default=0, help="0: until resumed")
    rp.add_argument("--group", help="a group's name; default: everyone")
    rr = rsub.add_parser("resume")
    rr.add_argument("--group", help="a group's name; default: everyone and every group")
    p.set_defaults(func=_rpz)

    p = sub.add_parser("stats", help="statistics")
    ssub = p.add_subparsers(dest="action", required=True)
    ssub.add_parser("collect")
    p.set_defaults(func=_stats)

    p = sub.add_parser("alerts", help="check for problems and notify (Settings → Alerts)")
    asub = p.add_subparsers(dest="action", required=True)
    asub.add_parser("check", help="evaluate and send notifications (dnsone-stats.timer runs this every minute)")
    asub.add_parser("test", help="send a test alert to every channel that is on")
    p.set_defaults(func=_alerts)

    p = sub.add_parser("cluster", help="nodes and secondaries (Phase 2)")
    csub = p.add_subparsers(dest="action", required=True)
    csub.add_parser("nodes")
    cp = csub.add_parser("secondary-config")
    cp.add_argument("--primary", required=True, help="the primary's address the secondary transfers from")
    cp.add_argument("--port", type=int, default=5301)
    p.set_defaults(func=_cluster)

    args = parser.parse_args(argv)
    logsetup.setup(f"ctl-{args.command}")
    try:
        return args.func(args)
    except TimeoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 75  # EX_TEMPFAIL: the timer simply runs again later


if __name__ == "__main__":
    sys.exit(main())
