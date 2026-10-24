"""Zone templates: listed for everyone who creates or edits zones, managed with templates.manage."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, templates, validation
from ..db import get_db
from ..models import ZoneTemplate
from .deps import Actor, ApiError, field_error, not_found, require

router = APIRouter(prefix="/api/templates", tags=["templates"])


def _clean(body: dict) -> dict:
    try:
        data = templates.clean(body)
        if not data["name"]:
            raise validation.ValidationError("name", "Give the template a name.")
        return data
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    except (TypeError, ValueError, AttributeError):
        raise ApiError(422, "The template is not in the expected form.") from None


@router.get("")
def list_templates(actor: Actor = Depends(require("zones.view")), db: Session = Depends(get_db)) -> dict:
    return {"rows": [templates.out(t) for t in db.scalars(select(ZoneTemplate).order_by(ZoneTemplate.name))]}


@router.get("/{template_id}")
def get_template(template_id: int, actor: Actor = Depends(require("zones.view")), db: Session = Depends(get_db)) -> dict:
    t = db.get(ZoneTemplate, template_id)
    if t is None:
        raise not_found("Template")
    return templates.out(t)


@router.post("", status_code=201)
def create_template(body: dict, actor: Actor = Depends(require("templates.manage")), db: Session = Depends(get_db)) -> dict:
    t = ZoneTemplate(**_clean(body), created_by=actor.name)
    db.add(t)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ApiError(409, "A template with this name already exists.", {"name": "This name is taken."}) from None
    audit.record(db, actor.name, "template.created", "template", t.id, {"name": t.name, "records": len(t.records)}, actor.ip)
    db.commit()
    db.refresh(t)
    return templates.out(t)


@router.put("/{template_id}")
def update_template(template_id: int, body: dict, actor: Actor = Depends(require("templates.manage")), db: Session = Depends(get_db)) -> dict:
    t = db.get(ZoneTemplate, template_id)
    if t is None:
        raise not_found("Template")
    before = templates.out(t)
    for key, value in _clean(body).items():
        setattr(t, key, value)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ApiError(409, "A template with this name already exists.", {"name": "This name is taken."}) from None
    after = templates.out(t)
    audit.record(db, actor.name, "template.updated", "template", t.id, {"name": t.name, "changed": [k for k in after if k not in ("updated_at",) and before[k] != after[k]]}, actor.ip)
    db.commit()
    db.refresh(t)
    return templates.out(t)


@router.delete("/{template_id}")
def delete_template(template_id: int, actor: Actor = Depends(require("templates.manage")), db: Session = Depends(get_db)) -> dict:
    t = db.get(ZoneTemplate, template_id)
    if t is None:
        raise not_found("Template")
    audit.record(db, actor.name, "template.deleted", "template", t.id, {"name": t.name}, actor.ip)
    db.delete(t)
    db.commit()
    return {"ok": True}
