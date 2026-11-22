"""Zeek logs (TSV, JSON lines, Zui/Brim JSON array) as incident events.

Reuses the vulnerability workflow's Zeek reader (parsers/zeek.records) for the file format, and
its connection rules (parsers/zeek._to_flow) so a session counts as completed, refused or
unanswered exactly as it does there. Unlike that workflow it keeps every stream's records as
events, with the Zeek ``uid`` that ties a conn record to its dns, http, ssl and files records.
"""
from __future__ import annotations

from ...parsers import zeek
from ...parsers._util import clean_ip, clean_port, clean_proto, parse_ts, text
from ...schema import ParseStats
from ..events import Event, Reject, time_basis

# What each Zeek stream becomes. Streams not listed keep their own name as the action.
STREAM_ACTIONS = {"conn": "connection", "dns": "dns_query", "http": "http_request", "ssl": "tls_session",
                  "files": "file_transfer", "smb_files": "smb_file", "smb_mapping": "smb_share",
                  "rdp": "rdp_session", "ssh": "ssh_session", "kerberos": "kerberos_request",
                  "ntlm": "ntlm_auth", "dce_rpc": "dce_rpc_call", "x509": "certificate",
                  "weird": "protocol_anomaly", "dhcp": "dhcp_lease", "smtp": "smtp_message",
                  "ftp": "ftp_command"}
# Fields that name what a record is about, used to group records in the timeline.
SUBJECT_FIELDS = ("query", "host", "server_name", "uri", "filename", "path", "name", "client",
                  "service", "assigned_addr", "mailfrom", "command")


def _outcome(rec: dict) -> tuple[str, str]:
    """completed / refused / attempted for a conn record, by the same rules as the flow reader.
    'completed' means packets went both ways; it says nothing about a login."""
    scratch = ParseStats(file="", fmt="zeek")
    flow = zeek._to_flow(rec, scratch)
    state = text(rec.get("conn_state"))
    if flow is None:
        return "unknown", state
    if flow.action == "reject":
        return "refused", state
    return ("completed" if flow.established else "attempted"), state


class ZeekAdapter:
    name = "zeek"
    version = "0.1"
    coverage = {
        "network": "Only traffic that passed the sensor's capture point; sessions behind NAT show the "
                   "translated address the sensor saw.",
        "conn": "A completed connection shows packets went both ways, not that a login or request succeeded.",
    }

    def accepts(self, path: str, detected: str) -> bool:
        return detected == "zeek"

    def read(self, path: str, evidence_id: str, stats: ParseStats, on_reject):
        def dropped(loc, reason):
            on_reject(Reject(loc, reason))
        seq = 0
        for loc, stream, rec in zeek.records(path, stats, on_drop=dropped):
            if stream in zeek.BOOKKEEPING_STREAMS:
                stats.drop("Zeek bookkeeping log, not network activity")
                continue
            seq += 1
            raw_ts = rec.get("ts") if rec.get("ts") is not None else rec.get("timestamp")
            ts = parse_ts(raw_ts)
            src = clean_ip(rec.get("id.orig_h") or rec.get("src") or rec.get("src_ip"))
            dst = clean_ip(rec.get("id.resp_h") or rec.get("dst") or rec.get("dest_ip"))
            ev = Event(
                evidence_id=evidence_id, locator=loc, seq=seq, provider="zeek", source_type=stream,
                category="network", action=STREAM_ACTIONS.get(stream, stream),
                event_time=ts, time_original="" if raw_ts is None else str(raw_ts),
                time_field="ts" if rec.get("ts") is not None else ("timestamp" if raw_ts is not None else ""),
                time_basis=time_basis(raw_ts), src_ip=src, dst_ip=dst,
                src_port=clean_port(rec.get("id.orig_p") or rec.get("src_port")),
                dst_port=clean_port(rec.get("id.resp_p") or rec.get("p") or rec.get("dest_port")),
                proto=clean_proto(rec.get("proto")) if rec.get("proto") else "",
                ids={"zeek_uid": rec.get("uid"), "community_id": rec.get("community_id"),
                     "zeek_fuid": rec.get("fuid")},
                fields=rec)
            if raw_ts is None or ts is None:
                stats.note("some records had no readable time (kept, listed as untimed)")
            if stream == "conn":
                if not src or not dst:
                    stats.drop("missing or invalid IP")
                    dropped(loc, "conn record without a valid source or destination address")
                    continue
                ev.outcome, ev.action_original = _outcome(rec)
                ev.outcome_reason = f"conn_state {ev.action_original}" if ev.action_original else ""
            elif stream == "notice":
                note = text(rec.get("note"))
                ev.action_original = note
                if note.startswith("CaptureLoss::"):
                    ev.category, ev.action = "sensor", "capture_loss"
                else:
                    ev.category, ev.action = "detection", "zeek_notice"
            elif stream == "alert" and rec.get("event_type") == "alert":
                ev.category, ev.action = "detection", "ids_alert"
                ev.action_original = text(rec.get("alert.signature"))
            elif stream in ("weird",):
                ev.action_original = text(rec.get("name"))
            if stream != "conn":
                subject = next((text(rec.get(k)) for k in SUBJECT_FIELDS if rec.get(k) not in (None, "", [])), "")
                if subject and not ev.action_original:
                    ev.action_original = subject[:300]
            stats.kept += 1
            yield ev
