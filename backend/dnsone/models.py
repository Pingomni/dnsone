"""ORM mapping of the schema in migrations/. The SQL files are the source of truth for DDL."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, BigInteger, Column, Computed, DateTime, FetchedValue, ForeignKey, Integer, LargeBinary, SmallInteger, String, Table, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(String(255), default="")
    permissions: Mapped[list] = mapped_column(JSON, default=list)
    built_in: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(128), default="")
    email: Mapped[str] = mapped_column(String(254), default="")
    password_hash: Mapped[str | None] = mapped_column(String(255))
    totp_secret: Mapped[str | None] = mapped_column(String(64))
    totp_enabled: Mapped[bool] = mapped_column(default=False)
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger)
    recovery_codes: Mapped[list | None] = mapped_column(JSON)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"))
    enabled: Mapped[bool] = mapped_column(default=True)
    auth_source: Mapped[str] = mapped_column(String(8), default="local")
    external_id: Mapped[str | None] = mapped_column(String(255))
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())

    role: Mapped[Role] = relationship(lazy="joined")


class SessionRow(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    csrf_token: Mapped[str] = mapped_column(String(43))
    ip: Mapped[str] = mapped_column(String(45), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")
    oidc_id_token: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)

    user: Mapped[User] = relationship(lazy="joined")


class Zone(Base):
    __tablename__ = "zones"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(253))
    description: Mapped[str] = mapped_column(String(255), default="")
    serial: Mapped[int] = mapped_column(Integer, default=0)
    default_ttl: Mapped[int] = mapped_column(Integer, default=3600)
    soa_mname: Mapped[str] = mapped_column(String(253))
    soa_rname: Mapped[str] = mapped_column(String(253))
    soa_refresh: Mapped[int] = mapped_column(Integer, default=7200)
    soa_retry: Mapped[int] = mapped_column(Integer, default=1800)
    soa_expire: Mapped[int] = mapped_column(Integer, default=1209600)
    soa_minimum: Mapped[int] = mapped_column(Integer, default=300)
    status: Mapped[str] = mapped_column(String(8), default="active")
    # off, on (BIND signs it) or insecure (signing being removed; see migration 0005).
    dnssec: Mapped[str] = mapped_column(String(8), default="off")
    revision: Mapped[int] = mapped_column(Integer, default=1)
    published_revision: Mapped[int] = mapped_column(Integer, default=0)
    publish_state: Mapped[str] = mapped_column(String(10), default="pending")
    published_serial: Mapped[int | None] = mapped_column(Integer)
    published_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())


class Record(Base):
    __tablename__ = "records"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    zone_id: Mapped[int] = mapped_column(ForeignKey("zones.id"))
    name: Mapped[str] = mapped_column(String(253))
    type: Mapped[str] = mapped_column(String(5))
    value: Mapped[str] = mapped_column(String(4000))
    ttl: Mapped[int | None] = mapped_column(Integer)
    priority: Mapped[int | None] = mapped_column(SmallInteger)
    disabled: Mapped[bool] = mapped_column(default=False)
    comment: Mapped[str] = mapped_column(String(255), default="")
    # STORED generated column (see the migration); the database computes it.
    rr_hash: Mapped[bytes] = mapped_column(LargeBinary(16), Computed("rr_hash", persisted=True))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())


class AuthChallenge(Base):
    __tablename__ = "auth_challenges"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    ip: Mapped[str] = mapped_column(String(45), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())
    expires_at: Mapped[datetime] = mapped_column(DateTime)

    user: Mapped[User] = relationship(lazy="joined")


class OidcLogin(Base):
    __tablename__ = "oidc_logins"

    state: Mapped[str] = mapped_column(String(43), primary_key=True)
    verifier: Mapped[str] = mapped_column(String(86))
    nonce: Mapped[str] = mapped_column(String(43))
    ip: Mapped[str] = mapped_column(String(45), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(64))
    token_hash: Mapped[str] = mapped_column(String(64))
    prefix: Mapped[str] = mapped_column(String(12))
    read_only: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_used_ip: Mapped[str] = mapped_column(String(45), default="")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)

    user: Mapped[User] = relationship(lazy="joined")


group_blocklists = Table(
    "client_group_blocklists",
    Base.metadata,
    Column("group_id", ForeignKey("client_groups.id"), primary_key=True),
    Column("blocklist_id", ForeignKey("blocklists.id"), primary_key=True),
)


class ClientGroup(Base):
    __tablename__ = "client_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(String(255), default="")
    blocking: Mapped[bool] = mapped_column(default=True)
    built_in: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())

    networks: Mapped[list["ClientGroupNetwork"]] = relationship(back_populates="group", cascade="all, delete-orphan", order_by="ClientGroupNetwork.network")
    blocklists: Mapped[list["Blocklist"]] = relationship(secondary=group_blocklists, back_populates="groups")


class ClientGroupNetwork(Base):
    __tablename__ = "client_group_networks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("client_groups.id"))
    network: Mapped[str] = mapped_column(String(49))
    comment: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())

    group: Mapped[ClientGroup] = relationship(back_populates="networks")


class RpzRule(Base):
    __tablename__ = "rpz_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pattern: Mapped[str] = mapped_column(String(253))
    # exact: a name or *.name (RPZ trigger). regex: a POSIX extended regular expression (dnsdist).
    match_type: Mapped[str] = mapped_column(String(5), default="exact")
    action: Mapped[str] = mapped_column(String(10))
    target: Mapped[str | None] = mapped_column(String(253))
    # NULL: every group.
    group_id: Mapped[int | None] = mapped_column(ForeignKey("client_groups.id"))
    group_key: Mapped[int] = mapped_column(Integer, Computed("group_key", persisted=True))
    source: Mapped[str] = mapped_column(String(64), default="manual")
    enabled: Mapped[bool] = mapped_column(default=True)
    comment: Mapped[str] = mapped_column(String(255), default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())


class Blocklist(Base):
    __tablename__ = "blocklists"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    url: Mapped[str] = mapped_column(String(2048))
    format: Mapped[str] = mapped_column(String(8), default="auto")
    # block: a blocklist. allow: an allowlist subscription (names never blocked).
    kind: Mapped[str] = mapped_column(String(5), default="block")
    enabled: Mapped[bool] = mapped_column(default=True)
    last_updated: Mapped[datetime | None] = mapped_column(DateTime)
    last_checked: Mapped[datetime | None] = mapped_column(DateTime)
    last_status: Mapped[str] = mapped_column(String(12), default="never")
    last_error: Mapped[str | None] = mapped_column(String(1024))
    domain_count: Mapped[int] = mapped_column(Integer, default=0)
    etag: Mapped[str | None] = mapped_column(String(255))
    last_modified: Mapped[str | None] = mapped_column(String(64))
    content_sha256: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())

    groups: Mapped[list[ClientGroup]] = relationship(secondary=group_blocklists, back_populates="blocklists")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    entity: Mapped[str] = mapped_column(String(32))
    entity_id: Mapped[str] = mapped_column(String(64), default="")
    payload_json: Mapped[dict | None] = mapped_column(JSON)
    ip: Mapped[str] = mapped_column(String(45), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())


class Setting(Base):
    __tablename__ = "settings"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=FetchedValue())


class StatsSample(Base):
    __tablename__ = "stats_samples"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    node: Mapped[str] = mapped_column(String(64))
    sampled_at: Mapped[datetime] = mapped_column(DateTime)
    queries: Mapped[int | None] = mapped_column(BigInteger)
    blocked: Mapped[int | None] = mapped_column(BigInteger)
    cache_hits: Mapped[int | None] = mapped_column(BigInteger)
    cache_misses: Mapped[int | None] = mapped_column(BigInteger)
    servfail: Mapped[int | None] = mapped_column(BigInteger)
    dropped: Mapped[int | None] = mapped_column(BigInteger)
