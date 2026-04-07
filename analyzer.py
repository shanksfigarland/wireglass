from __future__ import annotations

import argparse
import ipaddress
import json
import math
import pathlib
import statistics
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from triage_core import analyze_capture_path, print_terminal_report, write_json_report


PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN = {0x8100, 0x88A8}
TCP_SYN = 0x02
TCP_ACK = 0x10
TCP_FIN = 0x01
TCP_RST = 0x04

HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")


@dataclass(frozen=True)
class FlowKey:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str


@dataclass
class FlowStats:
    packets: int = 0
    bytes: int = 0
    payload_bytes: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    syn_packets: int = 0
    ack_packets: int = 0
    fin_packets: int = 0
    rst_packets: int = 0
    timestamps: list[float] = field(default_factory=list)
    app_protocols: Counter[str] = field(default_factory=Counter)

    def observe(self, ts: float, wire_bytes: int, payload_len: int, flags: int | None = None) -> None:
        self.packets += 1
        self.bytes += wire_bytes
        self.payload_bytes += payload_len
        self.first_seen = ts if self.first_seen is None else min(self.first_seen, ts)
        self.last_seen = ts if self.last_seen is None else max(self.last_seen, ts)
        self.timestamps.append(ts)
        if flags is None:
            return
        if flags & TCP_SYN:
            self.syn_packets += 1
        if flags & TCP_ACK:
            self.ack_packets += 1
        if flags & TCP_FIN:
            self.fin_packets += 1
        if flags & TCP_RST:
            self.rst_packets += 1

    @property
    def duration(self) -> float:
        if self.first_seen is None or self.last_seen is None:
            return 0.0
        return max(0.0, self.last_seen - self.first_seen)


@dataclass
class Detection:
    severity: str
    name: str
    summary: str
    details: dict[str, object]


def bytes_human(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def registered_domain(name: str) -> str:
    labels = [label for label in name.split(".") if label]
    if len(labels) < 2:
        return name
    return ".".join(labels[-2:])


def is_private_ip(address: str) -> bool:
    return ipaddress.ip_address(address).is_private


def parse_pcap(path: pathlib.Path):
    with path.open("rb") as handle:
        magic = handle.read(4)
        if magic == PCAPNG_MAGIC:
            raise ValueError("pcapng is not supported yet in this MVP. Use classic pcap for now.")
        if magic not in PCAP_MAGIC:
            raise ValueError("Unsupported capture format.")
        endian, ts_divisor = PCAP_MAGIC[magic]
        remainder = handle.read(20)
        if len(remainder) != 20:
            raise ValueError("Truncated pcap global header.")
        while True:
            packet_header = handle.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError("Truncated pcap packet header.")
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(f"{endian}IIII", packet_header)
            packet_data = handle.read(incl_len)
            if len(packet_data) != incl_len:
                raise ValueError("Truncated pcap packet payload.")
            yield (ts_sec + (ts_frac / ts_divisor), packet_data, incl_len, orig_len)


def parse_dns_name(data: bytes, offset: int, depth: int = 0) -> tuple[str | None, int]:
    if depth > 10:
        return None, offset
    labels: list[str] = []
    next_offset = offset
    while offset < len(data):
        length = data[offset]
        if length == 0:
            next_offset = offset + 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                return None, offset + 1
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            pointed_name, _ = parse_dns_name(data, pointer, depth + 1)
            if pointed_name:
                labels.append(pointed_name)
            next_offset = offset + 2
            break
        offset += 1
        if offset + length > len(data):
            return None, offset + length
        labels.append(data[offset : offset + length].decode("ascii", errors="ignore"))
        offset += length
        next_offset = offset
    return ".".join(part for part in labels if part), next_offset


def parse_dns_message(payload: bytes) -> dict[str, object] | None:
    if len(payload) < 12:
        return None
    txid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", payload[:12])
    offset = 12
    questions: list[str] = []
    for _ in range(qdcount):
        name, offset = parse_dns_name(payload, offset)
        if not name or offset + 4 > len(payload):
            break
        offset += 4
        questions.append(name)
    return {
        "transaction_id": txid,
        "is_response": bool(flags & 0x8000),
        "rcode": flags & 0x000F,
        "questions": questions,
        "answer_count": ancount,
    }


def parse_http_payload(payload: bytes) -> dict[str, object] | None:
    if not payload:
        return None
    text = payload[:4096].decode("latin-1", errors="ignore")
    lines = text.split("\r\n")
    first_line = lines[0].strip()
    if not first_line:
        return None
    if any(first_line.startswith(f"{method} ") for method in HTTP_METHODS):
        parts = first_line.split()
        headers = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            header_name, header_value = line.split(":", 1)
            headers[header_name.strip().lower()] = header_value.strip()
        return {
            "kind": "request",
            "method": parts[0],
            "path": parts[1] if len(parts) > 1 else "",
            "host": headers.get("host", ""),
            "user_agent": headers.get("user-agent", ""),
        }
    if first_line.startswith("HTTP/1."):
        parts = first_line.split()
        return {
            "kind": "response",
            "status_code": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None,
            "reason": " ".join(parts[2:]) if len(parts) > 2 else "",
        }
    return None


def parse_tls_client_hello(payload: bytes) -> dict[str, object] | None:
    offset = 0
    while offset + 5 <= len(payload):
        content_type = payload[offset]
        version_major = payload[offset + 1]
        record_length = struct.unpack("!H", payload[offset + 3 : offset + 5])[0]
        record_start = offset + 5
        record_end = record_start + record_length
        if version_major != 3 or record_end > len(payload):
            break
        record = payload[record_start:record_end]
        if content_type == 22 and len(record) >= 4 and record[0] == 1:
            hello_length = int.from_bytes(record[1:4], "big")
            body = record[4 : 4 + hello_length]
            if len(body) < 34:
                return None
            cursor = 34
            if cursor >= len(body):
                return None
            session_id_len = body[cursor]
            cursor += 1 + session_id_len
            if cursor + 2 > len(body):
                return None
            cipher_len = struct.unpack("!H", body[cursor : cursor + 2])[0]
            cursor += 2 + cipher_len
            if cursor >= len(body):
                return None
            compression_len = body[cursor]
            cursor += 1 + compression_len
            if cursor + 2 > len(body):
                return None
            extensions_length = struct.unpack("!H", body[cursor : cursor + 2])[0]
            cursor += 2
            end_extensions = min(len(body), cursor + extensions_length)
            server_name = ""
            while cursor + 4 <= end_extensions:
                extension_type, extension_len = struct.unpack("!HH", body[cursor : cursor + 4])
                cursor += 4
                extension_data = body[cursor : cursor + extension_len]
                cursor += extension_len
                if extension_type != 0 or len(extension_data) < 5:
                    continue
                server_name_list_len = struct.unpack("!H", extension_data[:2])[0]
                entry = extension_data[2 : 2 + server_name_list_len]
                if len(entry) < 3:
                    continue
                name_len = struct.unpack("!H", entry[1:3])[0]
                if 3 + name_len > len(entry):
                    continue
                server_name = entry[3 : 3 + name_len].decode("ascii", errors="ignore")
                break
            return {"server_name": server_name}
        offset = record_end
    return None


class PcapAnalyzer:
    def __init__(self) -> None:
        self.packet_count = 0
        self.total_bytes = 0
        self.unsupported_packets = 0
        self.layer4_counter: Counter[str] = Counter()
        self.app_counter: Counter[str] = Counter()
        self.host_bytes: Counter[str] = Counter()
        self.host_packets: Counter[str] = Counter()
        self.port_counter: Counter[int] = Counter()
        self.flows: dict[FlowKey, FlowStats] = {}
        self.dns_queries: list[dict[str, object]] = []
        self.http_events: list[dict[str, object]] = []
        self.tls_events: list[dict[str, object]] = []
        self.syn_tracker: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))

    def analyze_file(self, path: pathlib.Path) -> dict[str, object]:
        for timestamp, packet_data, _, orig_len in parse_pcap(path):
            self.packet_count += 1
            self.total_bytes += orig_len
            self._analyze_packet(timestamp, packet_data, orig_len)
        detections = self._run_detections()
        return self._build_report(path, detections)

    def _analyze_packet(self, timestamp: float, packet_data: bytes, wire_len: int) -> None:
        ipv4 = self._parse_ethernet_ipv4(packet_data)
        if not ipv4:
            self.unsupported_packets += 1
            return
        src_ip = ipv4["src_ip"]
        dst_ip = ipv4["dst_ip"]
        protocol = ipv4["protocol"]
        payload = ipv4["payload"]

        self.host_bytes[src_ip] += wire_len
        self.host_packets[src_ip] += 1

        if protocol == 6:
            self.layer4_counter["TCP"] += 1
            tcp = self._parse_tcp(payload)
            if not tcp:
                self.unsupported_packets += 1
                return
            flow_key = FlowKey(src_ip, dst_ip, tcp["src_port"], tcp["dst_port"], "TCP")
            flow = self.flows.setdefault(flow_key, FlowStats())
            flow.observe(timestamp, wire_len, len(tcp["payload"]), tcp["flags"])
            self.port_counter[tcp["dst_port"]] += 1

            if tcp["flags"] & TCP_SYN and not (tcp["flags"] & TCP_ACK):
                self.syn_tracker[src_ip][dst_ip].add(tcp["dst_port"])

            http = parse_http_payload(tcp["payload"])
            if http:
                flow.app_protocols["HTTP"] += 1
                self.app_counter["HTTP"] += 1
                self.http_events.append({"src_ip": src_ip, "dst_ip": dst_ip, **http})

            tls = parse_tls_client_hello(tcp["payload"])
            if tls:
                flow.app_protocols["TLS"] += 1
                self.app_counter["TLS"] += 1
                self.tls_events.append({"src_ip": src_ip, "dst_ip": dst_ip, **tls})

        elif protocol == 17:
            self.layer4_counter["UDP"] += 1
            udp = self._parse_udp(payload)
            if not udp:
                self.unsupported_packets += 1
                return
            flow_key = FlowKey(src_ip, dst_ip, udp["src_port"], udp["dst_port"], "UDP")
            flow = self.flows.setdefault(flow_key, FlowStats())
            flow.observe(timestamp, wire_len, len(udp["payload"]))
            self.port_counter[udp["dst_port"]] += 1

            if udp["src_port"] == 53 or udp["dst_port"] == 53:
                dns = parse_dns_message(udp["payload"])
                if dns:
                    flow.app_protocols["DNS"] += 1
                    self.app_counter["DNS"] += 1
                    for question in dns["questions"]:
                        self.dns_queries.append(
                            {
                                "timestamp": round(timestamp, 6),
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "query": question,
                                "is_response": dns["is_response"],
                                "rcode": dns["rcode"],
                            }
                        )
        elif protocol == 1:
            self.layer4_counter["ICMP"] += 1
        else:
            self.layer4_counter[f"IP_{protocol}"] += 1

    def _parse_ethernet_ipv4(self, packet_data: bytes) -> dict[str, object] | None:
        if len(packet_data) < 14:
            return None
        ether_type = struct.unpack("!H", packet_data[12:14])[0]
        offset = 14
        while ether_type in ETHERTYPE_VLAN:
            if len(packet_data) < offset + 4:
                return None
            ether_type = struct.unpack("!H", packet_data[offset + 2 : offset + 4])[0]
            offset += 4
        if ether_type != ETHERTYPE_IPV4 or len(packet_data) < offset + 20:
            return None
        version_ihl = packet_data[offset]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4
        if version != 4 or len(packet_data) < offset + ihl:
            return None
        total_length = struct.unpack("!H", packet_data[offset + 2 : offset + 4])[0]
        protocol = packet_data[offset + 9]
        src_ip = ".".join(str(part) for part in packet_data[offset + 12 : offset + 16])
        dst_ip = ".".join(str(part) for part in packet_data[offset + 16 : offset + 20])
        payload_start = offset + ihl
        payload_end = min(len(packet_data), offset + total_length if total_length else len(packet_data))
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "payload": packet_data[payload_start:payload_end],
        }

    def _parse_tcp(self, payload: bytes) -> dict[str, object] | None:
        if len(payload) < 20:
            return None
        src_port, dst_port, _, _, offset_reserved, flags, _, _, _ = struct.unpack("!HHIIBBHHH", payload[:20])
        data_offset = (offset_reserved >> 4) * 4
        if len(payload) < data_offset:
            return None
        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "flags": flags,
            "payload": payload[data_offset:],
        }

    def _parse_udp(self, payload: bytes) -> dict[str, object] | None:
        if len(payload) < 8:
            return None
        src_port, dst_port, length, _ = struct.unpack("!HHHH", payload[:8])
        udp_payload = payload[8:length] if length >= 8 else b""
        return {"src_port": src_port, "dst_port": dst_port, "payload": udp_payload}

    def _run_detections(self) -> list[Detection]:
        detections: list[Detection] = []
        detections.extend(self._detect_syn_scans())
        detections.extend(self._detect_dns_anomalies())
        detections.extend(self._detect_beacons())
        return sorted(
            detections,
            key=lambda item: ({"high": 0, "medium": 1, "low": 2}.get(item.severity, 3), item.name),
        )

    def _detect_syn_scans(self) -> list[Detection]:
        detections: list[Detection] = []
        for src_ip, targets in self.syn_tracker.items():
            total_ports = 0
            for dst_ip, ports in targets.items():
                total_ports += len(ports)
                if len(ports) >= 5:
                    detections.append(
                        Detection(
                            severity="high",
                            name="tcp_syn_scan",
                            summary=f"{src_ip} sent SYN probes to {len(ports)} ports on {dst_ip}.",
                            details={
                                "source_ip": src_ip,
                                "destination_ip": dst_ip,
                                "ports": sorted(ports),
                            },
                        )
                    )
            if total_ports >= 10:
                detections.append(
                    Detection(
                        severity="medium",
                        name="broad_syn_scanning",
                        summary=f"{src_ip} probed {total_ports} unique TCP ports across multiple destinations.",
                        details={"source_ip": src_ip, "unique_port_count": total_ports},
                    )
                )
        return detections

    def _detect_dns_anomalies(self) -> list[Detection]:
        grouped: dict[tuple[str, str], list[str]] = defaultdict(list)
        for entry in self.dns_queries:
            if entry["is_response"]:
                continue
            query = str(entry["query"])
            labels = [label for label in query.split(".") if label]
            if len(labels) < 3:
                continue
            grouped[(str(entry["src_ip"]), registered_domain(query))].append(query)

        detections: list[Detection] = []
        for (src_ip, domain), queries in grouped.items():
            unique_subdomains = {".".join(query.split(".")[:-2]) for query in queries}
            subdomain_lengths = [len(".".join(query.split(".")[:-2])) for query in queries]
            entropies = [shannon_entropy("".join(query.split(".")[:-2]).replace(".", "")) for query in queries]
            avg_length = statistics.fmean(subdomain_lengths) if subdomain_lengths else 0.0
            avg_entropy = statistics.fmean(entropies) if entropies else 0.0
            if len(queries) >= 5 and len(unique_subdomains) >= 5 and avg_length >= 18 and avg_entropy >= 3.0:
                detections.append(
                    Detection(
                        severity="high",
                        name="dns_tunneling_suspected",
                        summary=f"{src_ip} generated many long, high-entropy subdomains under {domain}.",
                        details={
                            "source_ip": src_ip,
                            "domain": domain,
                            "query_count": len(queries),
                            "average_subdomain_length": round(avg_length, 2),
                            "average_entropy": round(avg_entropy, 2),
                        },
                    )
                )
        return detections

    def _detect_beacons(self) -> list[Detection]:
        detections: list[Detection] = []
        for flow_key, flow in self.flows.items():
            if len(flow.timestamps) < 5:
                continue
            intervals = [b - a for a, b in zip(flow.timestamps, flow.timestamps[1:]) if b > a]
            if len(intervals) < 4:
                continue
            mean_interval = statistics.fmean(intervals)
            if mean_interval < 2:
                continue
            stdev = statistics.pstdev(intervals)
            jitter_ratio = stdev / mean_interval if mean_interval else 1.0
            avg_payload = flow.payload_bytes / max(flow.packets, 1)
            if jitter_ratio <= 0.15 and avg_payload <= 256:
                detections.append(
                    Detection(
                        severity="medium",
                        name="periodic_beaconing",
                        summary=(
                            f"{flow_key.src_ip}:{flow_key.src_port} talked to "
                            f"{flow_key.dst_ip}:{flow_key.dst_port} at near-regular intervals."
                        ),
                        details={
                            "source_ip": flow_key.src_ip,
                            "destination_ip": flow_key.dst_ip,
                            "destination_port": flow_key.dst_port,
                            "mean_interval_seconds": round(mean_interval, 3),
                            "jitter_ratio": round(jitter_ratio, 4),
                            "packet_count": flow.packets,
                        },
                    )
                )
        return detections

    def _build_report(self, path: pathlib.Path, detections: list[Detection]) -> dict[str, object]:
        top_talkers = [
            {"ip": ip, "packets": self.host_packets[ip], "bytes": self.host_bytes[ip]}
            for ip, _ in self.host_packets.most_common(10)
        ]
        top_ports = [{"port": port, "packets": count} for port, count in self.port_counter.most_common(10)]
        top_flows = [
            {
                "flow": f"{key.src_ip}:{key.src_port} -> {key.dst_ip}:{key.dst_port}/{key.protocol}",
                "packets": stats.packets,
                "bytes": stats.bytes,
                "duration_seconds": round(stats.duration, 6),
                "app_protocols": dict(stats.app_protocols),
            }
            for key, stats in sorted(self.flows.items(), key=lambda item: item[1].bytes, reverse=True)[:10]
        ]
        return {
            "capture_file": str(path),
            "stats": {
                "packets": self.packet_count,
                "bytes": self.total_bytes,
                "unsupported_packets": self.unsupported_packets,
                "flows": len(self.flows),
            },
            "top_talkers": top_talkers,
            "top_destination_ports": top_ports,
            "layer4_protocols": dict(self.layer4_counter),
            "application_protocols": dict(self.app_counter),
            "top_flows": top_flows,
            "dns_queries": self.dns_queries[:20],
            "http_events": self.http_events[:20],
            "tls_client_hellos": self.tls_events[:20],
            "detections": [
                {
                    "severity": item.severity,
                    "name": item.name,
                    "summary": item.summary,
                    "details": item.details,
                }
                for item in detections
            ],
        }


def print_report(report: dict[str, object]) -> None:
    stats = report["stats"]
    print("PCAP Triage Report")
    print(f"Capture: {report['capture_file']}")
    print(
        f"Packets: {stats['packets']} | Flows: {stats['flows']} | "
        f"Bytes: {bytes_human(int(stats['bytes']))} | Unsupported: {stats['unsupported_packets']}"
    )
    print()

    print("Top Talkers")
    for entry in report["top_talkers"]:
        print(f"  {entry['ip']:15} packets={entry['packets']:3} bytes={bytes_human(int(entry['bytes']))}")
    print()

    print("Top Destination Ports")
    for entry in report["top_destination_ports"]:
        print(f"  {entry['port']:5} packets={entry['packets']}")
    print()

    print("Application Protocols")
    app_protocols = report["application_protocols"]
    if not app_protocols:
        print("  none identified")
    else:
        for name, count in app_protocols.items():
            print(f"  {name:8} {count}")
    print()

    print("Detections")
    detections = report["detections"]
    if not detections:
        print("  none")
    else:
        for detection in detections:
            print(f"  [{detection['severity'].upper()}] {detection['summary']}")
    print()

    if report["http_events"]:
        print("HTTP Highlights")
        for event in report["http_events"][:5]:
            if event["kind"] == "request":
                print(
                    f"  {event['src_ip']} -> {event['dst_ip']} "
                    f"{event['method']} {event['host']}{event['path']}"
                )
            else:
                print(
                    f"  {event['src_ip']} -> {event['dst_ip']} "
                    f"status={event['status_code']} {event['reason']}"
                )
        print()

    if report["dns_queries"]:
        print("DNS Sample")
        for entry in report["dns_queries"][:5]:
            print(f"  {entry['src_ip']} -> {entry['dst_ip']} {entry['query']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline PCAP/PCAPNG triage analyzer.")
    parser.add_argument("capture", type=pathlib.Path, help="Path to a .pcap or .pcapng file")
    parser.add_argument("--json", dest="json_path", type=pathlib.Path, help="Write a JSON report to this path")
    parser.add_argument("--external-intel", action="store_true", help="Enable external provider lookups for hashes and domains")
    parser.add_argument("--virustotal-key", default="", help="VirusTotal API key for external enrichment")
    parser.add_argument("--malwarebazaar-key", default="", help="MalwareBazaar Auth-Key for external enrichment")
    args = parser.parse_args()

    external_lookup_config = {
        "enabled": bool(args.external_intel),
        "providers": {
            "virustotal": {"enabled": bool(args.external_intel), "api_key": args.virustotal_key},
            "malwarebazaar": {"enabled": bool(args.external_intel), "api_key": args.malwarebazaar_key},
        },
    }
    report = analyze_capture_path(args.capture, external_lookup_config=external_lookup_config)
    print_terminal_report(report)

    if args.json_path:
        write_json_report(report, args.json_path)
        print()
        print(f"JSON report written to {args.json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
