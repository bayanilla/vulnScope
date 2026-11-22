"""Suricata EVE JSON parser: `alert` events become threat events, `flow` events become flows."""
from __future__ import annotations

import json

from ..schema import Flow, ParseStats, ThreatEvent
from ._util import clean_ip, clean_port, clean_proto, count, obj, open_text, parse_ts, text


def parse(path: str, stats: ParseStats):
    with open_text(path) as fh:
        for line in fh:
            if not line.strip():
                continue
            stats.read += 1
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                stats.drop("malformed JSON")
                continue
            if not isinstance(ev, dict):
                stats.drop("malformed JSON")
                continue
            kind = text(ev.get("event_type"))
            if kind not in ("alert", "flow"):
                stats.drop(f"{kind} events not used")
                continue
            src, dst = clean_ip(ev.get("src_ip")), clean_ip(ev.get("dest_ip"))
            if not src or not dst:
                stats.drop("missing or invalid IP")
                continue
            if kind == "alert":
                a = obj(ev.get("alert"))
                yield (ThreatEvent(ts=parse_ts(ev.get("timestamp")), src_ip=src, dst_ip=dst,
                                       dst_port=clean_port(ev.get("dest_port")),
                                       name=text(a.get("signature")) or "Suricata alert",
                                       severity=str(a.get("severity", "")),
                                       action="block" if a.get("action") == "blocked" else "alert"))
            else:
                f = obj(ev.get("flow"))
                b_out, b_in = count(f.get("bytes_toserver")), count(f.get("bytes_toclient"))
                sport, dport = clean_port(ev.get("src_port")), clean_port(ev.get("dest_port"))
                proto = clean_proto(ev.get("proto"))
                if _server_first(ev, proto, sport, dport):
                    # Suricata joined this TCP session mid-stream and took the first packet it saw,
                    # the server's reply, as the client. Turn it round so the server is the responder
                    # (Zeek does the same), or the reply looks like an inbound session to a high port.
                    src, dst, sport, dport, b_out, b_in = dst, src, dport, sport, b_in, b_out
                    p_out, p_in = count(f.get("pkts_toclient")), count(f.get("pkts_toserver"))
                else:
                    p_out, p_in = count(f.get("pkts_toserver")), count(f.get("pkts_toclient"))
                established = ((f.get("state") in ("established", "closed") and b_in > 0)
                               # a TCP session joined mid-stream: both sides sent data. (Not UDP:
                               # Suricata counts an ICMP error about a UDP flow as a reply.)
                               or (proto == "tcp" and p_out > 0 and p_in > 0 and b_out > 0 and b_in > 0))
                yield (Flow(ts=parse_ts(f.get("start") or ev.get("timestamp")), src_ip=src, dst_ip=dst,
                                src_port=sport, dst_port=dport, proto=proto,
                                action="deny" if f.get("action") == "drop" else "allow",
                                established=established,
                                bytes_out=b_out, bytes_in=b_in, app=text(ev.get("app_proto"))))


def _server_first(ev: dict, proto: str, sport, dport) -> bool:
    """A TCP flow Suricata picked up without seeing its SYN, whose "client" port is a service port
    (below 1024) and whose "server" port is a high, ephemeral one."""
    if proto != "tcp" or sport is None or dport is None:
        return False
    tcp = obj(ev.get("tcp"))
    if tcp.get("syn"):
        return False
    return sport < 1024 <= dport
