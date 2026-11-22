"""An incident case on disk: the case form, preserved evidence and the audit log.

Evidence is stored once per case by its SHA-256, under evidence/<sha256>/<original name>, and
made read-only. Uploading the same file again records the upload but stores nothing new. Every
change and every read of evidence or reports goes to audit.jsonl, where each line carries the hash
of the line before it, so a removed or edited line shows up in ``verify_audit``.
"""
from __future__ import annotations

import getpass
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from ..errors import UserError

CASE_FILE, EVIDENCE_FILE, AUDIT_FILE = "case.json", "evidence.json", "audit.jsonl"
CASE_VERSION = 1
NAME_MAX, NOTES_MAX = 200, 10_000
_GENESIS = "0" * 64


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def actor_name(given: str | None = None) -> str:
    """Who is acting: --actor, else $VULNSCOPE_ACTOR, else the account running the command."""
    name = (given or os.environ.get("VULNSCOPE_ACTOR") or "").strip()
    if not name:
        try:
            name = getpass.getuser()
        except Exception:
            name = "unknown"
    return name[:100]


def parse_time(value: str | None, what: str) -> str | None:
    """An ISO time from the case form, as UTC 'YYYY-MM-DDTHH:MM:SSZ'. A time without a zone is
    refused: the case window must not depend on the machine's clock setting."""
    if not value:
        return None
    s = value.strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise UserError(f"{what}: '{value}' is not a time. Use ISO format with a zone, "
                        "e.g. 2026-11-18T06:00:00Z.") from None
    if dt.tzinfo is None:
        raise UserError(f"{what}: '{value}' has no time zone. Add Z for UTC or an offset such as -05:00.")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Case:
    dir: str
    data: dict

    @property
    def case_id(self) -> str:
        return self.data["case_id"]

    def path(self, *parts: str) -> str:
        return os.path.join(self.dir, *parts)

    # ---------------------------------------------------------------- evidence registry
    def evidence(self) -> list[dict]:
        try:
            with open(self.path(EVIDENCE_FILE), encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            return []

    def save_evidence(self, records: list[dict]) -> None:
        _write_json(self.path(EVIDENCE_FILE), records)

    def evidence_path(self, rec: dict) -> str:
        return self.path(rec["stored_path"])

    # ---------------------------------------------------------------- audit
    def audit(self, actor: str, action: str, **details) -> dict:
        path = self.path(AUDIT_FILE)
        prev, seq = _GENESIS, 0
        if os.path.exists(path):
            last = _last_line(path)
            if last:
                entry = json.loads(last)
                prev, seq = entry["hash"], entry["seq"]
        entry = {"seq": seq + 1, "time": now_iso(), "case_id": self.case_id, "actor": actor,
                 "action": action, "details": details, "prev": prev}
        entry["hash"] = _entry_hash(entry)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
        return entry


def create(directory: str, name: str, *, actor: str, scope_nets=(), scope_hosts=(), scope_accounts=(),
           start: str | None = None, end: str | None = None, margin_minutes: int = 60,
           entities=(), notes: str = "") -> Case:
    """Create a case folder. The folder must be new or empty."""
    name = " ".join((name or "").split())[:NAME_MAX]
    if not name:
        raise UserError("A case needs a name.")
    if os.path.exists(directory) and os.listdir(directory):
        raise UserError(f"{directory} already exists and is not empty; choose a new folder for the case.")
    nets = []
    for n in scope_nets:
        try:
            nets.append(str(ipaddress.ip_network(n.strip(), strict=False)))
        except ValueError:
            raise UserError(f"Scope: '{n}' is not an address range, e.g. 10.20.0.0/16.") from None
    start_iso, end_iso = parse_time(start, "Window start"), parse_time(end, "Window end")
    if start_iso and end_iso and start_iso > end_iso:
        raise UserError("The window ends before it starts.")
    if margin_minutes < 0:
        raise UserError("The window margin cannot be negative.")
    os.makedirs(directory, mode=0o700, exist_ok=True)
    data = {
        "case_version": CASE_VERSION, "case_id": uuid.uuid4().hex, "name": name,
        "created": now_iso(), "created_by": actor,
        "scope": {"networks": nets, "hosts": _clean_list(scope_hosts), "accounts": _clean_list(scope_accounts)},
        "window": {"start": start_iso, "end": end_iso, "margin_minutes": int(margin_minutes)},
        "entities": _clean_list(entities), "notes": (notes or "").strip()[:NOTES_MAX],
    }
    _write_json(os.path.join(directory, CASE_FILE), data)
    case = Case(os.path.abspath(directory), data)
    case.save_evidence([])
    case.audit(actor, "case_created", name=name)
    return case


def open_case(directory: str) -> Case:
    path = os.path.join(directory, CASE_FILE)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise UserError(f"{directory} is not an incident case folder (no {CASE_FILE}).") from None
    except json.JSONDecodeError as exc:
        raise UserError(f"{path} is damaged: {exc}") from None
    if data.get("case_version") != CASE_VERSION or "case_id" not in data:
        raise UserError(f"{path} is not a case this version can open.")
    return Case(os.path.abspath(directory), data)


def sha256_file(path: str, chunk: int = 1 << 20) -> tuple[str, int]:
    h, size = hashlib.sha256(), 0
    with open(path, "rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
            size += len(block)
    return h.hexdigest(), size


def add_evidence(case: Case, src: str, actor: str, max_bytes: int | None = None) -> tuple[dict, bool]:
    """Store one file in the case. Returns (its evidence record, True if newly stored).

    The copy is checked against the hash of the source before it counts as stored, so an
    interrupted copy is never registered. The same content already in the case is recorded as a
    duplicate upload and not stored again."""
    if not os.path.isfile(src):
        raise UserError(f"{src}: not a file.")
    size = os.path.getsize(src)
    if max_bytes is not None and size > max_bytes:
        raise UserError(f"{os.path.basename(src)}: {size} bytes is over the case's limit of {max_bytes} bytes.")
    digest, _ = sha256_file(src)
    original = os.path.basename(src)
    records = case.evidence()
    for rec in records:
        if rec["sha256"] == digest:
            rec.setdefault("duplicate_uploads", []).append(
                {"original_name": original, "uploaded_by": actor, "uploaded_at": now_iso()})
            case.save_evidence(records)
            case.audit(actor, "evidence_duplicate", evidence_id=rec["evidence_id"], sha256=digest,
                       original_name=original)
            return rec, False
    folder = case.path("evidence", digest)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", original)[:150] or "evidence"
    dest = os.path.join(folder, safe)
    tmp = dest + ".partial"
    shutil.copyfile(src, tmp)
    got, got_size = sha256_file(tmp)
    if got != digest or got_size != size:
        os.remove(tmp)
        raise UserError(f"{original}: the stored copy does not match the original (file changed while copying?).")
    os.replace(tmp, dest)
    os.chmod(dest, stat.S_IRUSR)              # originals are never written again
    rec = {"evidence_id": digest[:16], "sha256": digest, "size": size, "original_name": original,
           "stored_path": os.path.relpath(dest, case.dir), "uploaded_by": actor, "uploaded_at": now_iso(),
           "status": "stored", "detected_format": None, "adapter": None, "adapter_version": None,
           "status_detail": "", "duplicate_uploads": []}
    records.append(rec)
    case.save_evidence(records)
    case.audit(actor, "evidence_stored", evidence_id=rec["evidence_id"], sha256=digest, size=size,
               original_name=original)
    return rec, True


def verify_audit(case: Case) -> list[str]:
    """Problems in the audit chain, as readable lines (empty when intact)."""
    problems, prev, seq = [], _GENESIS, 0
    try:
        fh = open(case.path(AUDIT_FILE), encoding="utf-8")
    except FileNotFoundError:
        return ["audit.jsonl is missing"]
    with fh:
        for n, line in enumerate(fh, 1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                problems.append(f"line {n}: not valid JSON")
                continue
            if entry.get("prev") != prev:
                problems.append(f"line {n}: does not follow the line before it (a line was removed or changed)")
            if entry.get("seq") != seq + 1:
                problems.append(f"line {n}: sequence {entry.get('seq')} where {seq + 1} was expected")
            if _entry_hash(entry) != entry.get("hash"):
                problems.append(f"line {n}: content does not match its hash (edited)")
            prev, seq = entry.get("hash", ""), entry.get("seq", seq + 1)
    return problems


def _entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _last_line(path: str) -> str:
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        end = fh.tell()
        pos, buf = end, b""
        while pos > 0:
            step = min(4096, pos)
            pos -= step
            fh.seek(pos)
            buf = fh.read(step) + buf
            if buf.rstrip(b"\n").count(b"\n") >= 1:
                break
    lines = buf.rstrip(b"\n").split(b"\n")
    return lines[-1].decode("utf-8") if lines and lines[-1] else ""


def _clean_list(values) -> list[str]:
    out = []
    for v in values or ():
        for part in str(v).split(","):
            part = part.strip()
            if part and part not in out:
                out.append(part[:200])
    return out


def _write_json(path: str, data) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, path)
