from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import math
import pathlib
import re
import statistics
import struct
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from external_intel import normalize_external_lookup_config, run_external_enrichment


PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
PCAPNG_BLOCK_SECTION_HEADER = 0x0A0D0D0A
PCAPNG_BLOCK_INTERFACE_DESCRIPTION = 0x00000001
PCAPNG_BLOCK_PACKET = 0x00000002
PCAPNG_BLOCK_SIMPLE_PACKET = 0x00000003
PCAPNG_BLOCK_ENHANCED_PACKET = 0x00000006

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = {0x8100, 0x88A8}

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10

COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3389}
HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")
IPV6_EXTENSION_HEADERS = {0, 43, 44, 50, 51, 60}
KERBEROS_PORTS = {88}
LDAP_PORTS = {389, 3268}
LDAPS_PORTS = {636, 3269}
SMB_PORTS = {445}
RPC_PORTS = {135}
AD_DISCOVERY_PORTS = {53, 88, 135, 389, 445, 636, 3268, 3269}
KERBEROS_MESSAGE_TAGS = {
    0x6A: "AS-REQ",
    0x6B: "AS-REP",
    0x6C: "TGS-REQ",
    0x6D: "TGS-REP",
    0x6E: "AP-REQ",
    0x6F: "AP-REP",
    0x7E: "KRB-ERROR",
}
LDAP_OPERATION_TAGS = {
    0x60: "BindRequest",
    0x61: "BindResponse",
    0x63: "SearchRequest",
    0x64: "SearchResultEntry",
    0x65: "SearchResultDone",
    0x66: "ModifyRequest",
    0x67: "ModifyResponse",
    0x68: "AddRequest",
    0x69: "AddResponse",
    0x6A: "DelRequest",
    0x6B: "DelResponse",
    0x6C: "ModifyDNRequest",
    0x6D: "ModifyDNResponse",
    0x6E: "CompareRequest",
    0x6F: "CompareResponse",
    0x77: "ExtendedRequest",
    0x78: "ExtendedResponse",
}
SMB2_COMMANDS = {
    0x0000: "NEGOTIATE",
    0x0001: "SESSION_SETUP",
    0x0003: "TREE_CONNECT",
    0x0005: "CREATE",
    0x000B: "IOCTL",
}
DCE_RPC_TYPES = {
    0: "request",
    2: "response",
    11: "bind",
    12: "bind_ack",
}
LDAP_ENUM_KEYWORDS = (
    "samaccountname",
    "serviceprincipalname",
    "admincount",
    "memberof",
    "useraccountcontrol",
    "objectclass",
    "memberof",
    "msds-allowedtodelegateto",
    "msds-allowedtoactonbehalfofotheridentity",
    "trustedtoauthfordelegation",
    "trustedfordelegation",
)
LDAP_DELEGATION_KEYWORDS = (
    "msds-allowedtodelegateto",
    "msds-allowedtoactonbehalfofotheridentity",
    "trustedtoauthfordelegation",
    "trustedfordelegation",
    "useraccountcontrol",
)
KERBEROS_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9._/\-$@]{5,}")
DRSUAPI_UUID_BYTES = uuid.UUID("e3514235-4b06-11d1-ab04-00c04fc2dcd2").bytes_le
SUSPICIOUS_ARTIFACT_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".jar",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".ps1",
    ".bat",
    ".cmd",
    ".hta",
    ".docm",
    ".xlsm",
    ".zip",
    ".7z",
    ".rar",
}
EXECUTABLE_SIGNATURES = (
    (b"MZ", "PE"),
    (b"\x7fELF", "ELF"),
    (b"PK\x03\x04", "ZIP"),
    (b"%PDF", "PDF"),
)
MAX_HTTP_BODY_BYTES = 8 * 1024 * 1024
MAX_TIMELINE_EVENTS = 120
INTEL_DB_PATH = pathlib.Path(__file__).resolve().parent / "intel" / "known_iocs.json"
LINKTYPE_NAMES = {
    LINKTYPE_NULL: "NULL",
    LINKTYPE_ETHERNET: "ETHERNET",
    LINKTYPE_RAW: "RAW",
    LINKTYPE_LINUX_SLL: "LINUX_SLL",
}
INTERNAL_V4_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10")
)
INTERNAL_V6_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in ("fc00::/7", "fe80::/10", "::1/128"))


class CaptureFormatError(ValueError):
    pass


@dataclass(frozen=True)
class PacketRecord:
    timestamp: float
    packet_data: bytes
    wire_len: int
    linktype: int


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
class HostStats:
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    peers: set[str] = field(default_factory=set)

    @property
    def total_packets(self) -> int:
        return self.packets_sent + self.packets_received

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received


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


def is_private_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in network for network in INTERNAL_V4_NETWORKS)
    return any(ip in network for network in INTERNAL_V6_NETWORKS)


def registered_domain(name: str) -> str:
    labels = [label for label in name.split(".") if label]
    if len(labels) < 2:
        return name
    return ".".join(labels[-2:])


def iso_utc(timestamp: float | None) -> str | None:
    if timestamp is None or timestamp <= 0:
        return None
    return dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).isoformat()


def classify_host(address: str) -> str:
    return "internal" if is_private_ip(address) else "external"


def linktype_name(linktype: int) -> str:
    return LINKTYPE_NAMES.get(linktype, f"LINKTYPE_{linktype}")


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


def read_ber_length(data: bytes, offset: int) -> tuple[int | None, int]:
    if offset >= len(data):
        return None, offset
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4 or offset + count > len(data):
        return None, offset
    return int.from_bytes(data[offset : offset + count], "big"), offset + count


def extract_ascii_tokens(payload: bytes) -> list[str]:
    text = payload.decode("latin-1", errors="ignore")
    tokens = KERBEROS_TOKEN_PATTERN.findall(text)
    filtered: list[str] = []
    for token in tokens:
        lowered = token.lower()
        if token.isdigit():
            continue
        if len(token) > 48:
            token = token[:48]
        if lowered in {"http", "tcp", "udp"}:
            continue
        filtered.append(token)
    return filtered[:12]


def parse_kerberos_message(payload: bytes) -> dict[str, object] | None:
    body = payload
    if len(body) >= 4:
        announced = int.from_bytes(body[:4], "big")
        if 1 <= announced <= len(body) - 4 and body[4] in KERBEROS_MESSAGE_TAGS:
            body = body[4 : 4 + announced]
    if not body or body[0] not in KERBEROS_MESSAGE_TAGS:
        return None
    message_name = KERBEROS_MESSAGE_TAGS[body[0]]
    tokens = [
        token
        for token in extract_ascii_tokens(body)
        if "/" in token or token.lower().startswith(("krbtgt", "ldap", "http", "cifs", "mssqlsvc"))
    ]
    return {"message_name": message_name, "token_sample": sorted(set(tokens))[:6]}


def parse_ldap_message(payload: bytes) -> dict[str, object] | None:
    if len(payload) < 6 or payload[0] != 0x30:
        return None
    _, offset = read_ber_length(payload, 1)
    if offset >= len(payload) or payload[offset] != 0x02:
        return None
    integer_length, offset = read_ber_length(payload, offset + 1)
    if integer_length is None or offset + integer_length > len(payload):
        return None
    message_id = int.from_bytes(payload[offset : offset + integer_length], "big", signed=False)
    offset += integer_length
    if offset >= len(payload):
        return None
    protocol_tag = payload[offset]
    operation = LDAP_OPERATION_TAGS.get(protocol_tag, f"Tag0x{protocol_tag:02X}")
    decoded = payload.decode("latin-1", errors="ignore").lower()
    matched_keywords = sorted({keyword for keyword in LDAP_ENUM_KEYWORDS if keyword in decoded})
    delegation_keywords = sorted({keyword for keyword in LDAP_DELEGATION_KEYWORDS if keyword in decoded})
    return {
        "message_id": message_id,
        "operation": operation,
        "keywords": matched_keywords,
        "delegation_keywords": delegation_keywords,
    }


def parse_netbios_session_payload(payload: bytes) -> bytes:
    if len(payload) < 4:
        return payload
    if payload[0] not in {0x00, 0x81, 0x82, 0x83, 0x84}:
        return payload
    length = int.from_bytes(payload[1:4], "big")
    if 0 < length <= len(payload) - 4:
        return payload[4 : 4 + length]
    return payload


def parse_smb_message(payload: bytes) -> dict[str, object] | None:
    body = parse_netbios_session_payload(payload)
    if body.startswith(b"\xfeSMB") and len(body) >= 16:
        command = struct.unpack("<H", body[12:14])[0]
        return {"version": "SMB2", "command": SMB2_COMMANDS.get(command, f"0x{command:04X}")}
    if body.startswith(b"\xffSMB") and len(body) >= 5:
        command = body[4]
        return {"version": "SMB1", "command": f"0x{command:02X}"}
    return None


def parse_dce_rpc_message(payload: bytes) -> dict[str, object] | None:
    body = parse_netbios_session_payload(payload)
    contains_drsuapi = DRSUAPI_UUID_BYTES in body
    if len(body) < 16:
        if contains_drsuapi:
            return {"packet_type": "embedded", "contains_drsuapi": True}
        return None
    if body[0] != 5:
        if contains_drsuapi:
            return {"packet_type": "embedded", "contains_drsuapi": True}
        return None
    packet_type = DCE_RPC_TYPES.get(body[2], f"type_{body[2]}")
    return {"packet_type": packet_type, "contains_drsuapi": contains_drsuapi}


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_http_headers(header_text: str) -> tuple[str, dict[str, str]]:
    lines = header_text.split("\r\n")
    first_line = lines[0].strip() if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return first_line, headers


def scan_http_requests(stream: bytes) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []
    cursor = 0
    while cursor < len(stream):
        marker = -1
        for method in HTTP_METHODS:
            candidate = stream.find(method.encode("ascii") + b" ", cursor)
            if candidate != -1 and (marker == -1 or candidate < marker):
                marker = candidate
        if marker == -1:
            break
        header_end = stream.find(b"\r\n\r\n", marker)
        if header_end == -1:
            break
        header_blob = stream[marker:header_end].decode("latin-1", errors="ignore")
        first_line, headers = parse_http_headers(header_blob)
        parts = first_line.split()
        requests.append(
            {
                "method": parts[0] if parts else "GET",
                "path": parts[1] if len(parts) > 1 else "",
                "host": headers.get("host", ""),
                "headers": headers,
            }
        )
        cursor = header_end + 4
    return requests


def scan_http_responses(stream: bytes) -> list[dict[str, object]]:
    responses: list[dict[str, object]] = []
    cursor = 0
    while cursor < len(stream):
        marker = stream.find(b"HTTP/1.", cursor)
        if marker == -1:
            break
        header_end = stream.find(b"\r\n\r\n", marker)
        if header_end == -1:
            break
        header_blob = stream[marker:header_end].decode("latin-1", errors="ignore")
        first_line, headers = parse_http_headers(header_blob)
        parts = first_line.split()
        content_length = 0
        try:
            content_length = int(headers.get("content-length", "0"))
        except ValueError:
            content_length = 0
        if content_length > MAX_HTTP_BODY_BYTES:
            content_length = MAX_HTTP_BODY_BYTES
        body_start = header_end + 4
        body_end = min(len(stream), body_start + content_length)
        responses.append(
            {
                "status_code": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None,
                "reason": " ".join(parts[2:]) if len(parts) > 2 else "",
                "headers": headers,
                "body": stream[body_start:body_end],
                "complete": (body_end - body_start) == content_length,
            }
        )
        cursor = body_end if body_end > body_start else header_end + 4
    return responses


def guess_artifact_type(body: bytes, headers: dict[str, str], path_hint: str) -> tuple[str, bool]:
    lower_path = path_hint.lower()
    extension = pathlib.PurePosixPath(lower_path).suffix
    if extension in SUSPICIOUS_ARTIFACT_EXTENSIONS:
        return extension.lstrip("."), True
    content_type = headers.get("content-type", "").lower()
    if "application/octet-stream" in content_type:
        return "binary", True
    for signature, label in EXECUTABLE_SIGNATURES:
        if body.startswith(signature):
            return label, label in {"PE", "ELF", "ZIP"}
    if content_type.startswith("text/"):
        return "text", False
    return "unknown", False


def load_local_intel() -> dict[str, object]:
    default = {"hashes": {}, "domains": {}, "filenames": {}}
    if not INTEL_DB_PATH.exists():
        return default
    try:
        loaded = json.loads(INTEL_DB_PATH.read_text(encoding="utf-8"))
    except Exception:
        return default
    if not isinstance(loaded, dict):
        return default
    for key in default:
        if key not in loaded or not isinstance(loaded[key], dict):
            loaded[key] = {}
    return loaded


def detect_capture_format(data: bytes) -> str:
    if len(data) < 4:
        raise CaptureFormatError("Capture file is too small to identify.")
    magic = data[:4]
    if magic in PCAP_MAGIC:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    raise CaptureFormatError("Unsupported capture format. Expected classic pcap or pcapng.")


def parse_pcap_records(data: bytes) -> list[PacketRecord]:
    magic = data[:4]
    if magic not in PCAP_MAGIC or len(data) < 24:
        raise CaptureFormatError("Invalid pcap file.")
    endian, ts_divisor = PCAP_MAGIC[magic]
    _, _, _, _, _, _, linktype = struct.unpack(f"{endian}IHHIIII", data[:24])
    offset = 24
    records: list[PacketRecord] = []
    while offset + 16 <= len(data):
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(f"{endian}IIII", data[offset : offset + 16])
        offset += 16
        packet_end = offset + incl_len
        if packet_end > len(data):
            raise CaptureFormatError("Truncated pcap packet payload.")
        packet_data = data[offset:packet_end]
        offset = packet_end
        records.append(
            PacketRecord(
                timestamp=ts_sec + (ts_frac / ts_divisor),
                packet_data=packet_data,
                wire_len=orig_len,
                linktype=linktype,
            )
        )
    return records


def iter_pcapng_options(option_bytes: bytes, endian: str):
    cursor = 0
    while cursor + 4 <= len(option_bytes):
        code, length = struct.unpack(f"{endian}HH", option_bytes[cursor : cursor + 4])
        cursor += 4
        if code == 0:
            break
        value = option_bytes[cursor : cursor + length]
        cursor += length
        cursor += (4 - (length % 4)) % 4
        yield code, value


def pcapng_ts_divisor(value: int) -> int:
    if value & 0x80:
        return 2 ** (value & 0x7F)
    return 10 ** value


def parse_pcapng_records(data: bytes, warnings: list[str]) -> list[PacketRecord]:
    if len(data) < 28:
        raise CaptureFormatError("Invalid pcapng file.")
    offset = 0
    endian = "<"
    interfaces: list[dict[str, int]] = []
    records: list[PacketRecord] = []

    while offset + 12 <= len(data):
        block_type_le = struct.unpack("<I", data[offset : offset + 4])[0]
        if block_type_le == PCAPNG_BLOCK_SECTION_HEADER:
            bom = data[offset + 8 : offset + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise CaptureFormatError("Invalid pcapng byte-order magic.")
            block_total_length = struct.unpack(f"{endian}I", data[offset + 4 : offset + 8])[0]
            if block_total_length < 28 or offset + block_total_length > len(data):
                raise CaptureFormatError("Invalid pcapng section header block length.")
            interfaces = []
        else:
            if offset + 8 > len(data):
                raise CaptureFormatError("Truncated pcapng block header.")
            block_total_length = struct.unpack(f"{endian}I", data[offset + 4 : offset + 8])[0]
            if block_total_length < 12 or offset + block_total_length > len(data):
                raise CaptureFormatError("Invalid pcapng block length.")

        trailer = struct.unpack(f"{endian}I", data[offset + block_total_length - 4 : offset + block_total_length])[0]
        if trailer != block_total_length:
            raise CaptureFormatError("Mismatched pcapng block lengths.")

        body = data[offset + 8 : offset + block_total_length - 4]
        block_type = struct.unpack(f"{endian}I", data[offset : offset + 4])[0]

        if block_type == PCAPNG_BLOCK_INTERFACE_DESCRIPTION:
            if len(body) < 8:
                raise CaptureFormatError("Truncated pcapng interface description block.")
            linktype, _, _ = struct.unpack(f"{endian}HHI", body[:8])
            ts_divisor = 1_000_000
            for code, value in iter_pcapng_options(body[8:], endian):
                if code == 9 and value:
                    ts_divisor = pcapng_ts_divisor(value[0])
            interfaces.append({"linktype": linktype, "ts_divisor": ts_divisor})

        elif block_type == PCAPNG_BLOCK_ENHANCED_PACKET:
            if len(body) < 20:
                raise CaptureFormatError("Truncated pcapng enhanced packet block.")
            interface_id, ts_high, ts_low, captured_len, packet_len = struct.unpack(f"{endian}IIIII", body[:20])
            if interface_id >= len(interfaces):
                warnings.append("Encountered an enhanced packet block with an unknown interface.")
            else:
                packet_data = body[20 : 20 + captured_len]
                if len(packet_data) != captured_len:
                    raise CaptureFormatError("Truncated pcapng packet data.")
                timestamp_raw = (ts_high << 32) | ts_low
                records.append(
                    PacketRecord(
                        timestamp=timestamp_raw / interfaces[interface_id]["ts_divisor"],
                        packet_data=packet_data,
                        wire_len=packet_len,
                        linktype=interfaces[interface_id]["linktype"],
                    )
                )

        elif block_type == PCAPNG_BLOCK_SIMPLE_PACKET:
            if len(body) < 4:
                raise CaptureFormatError("Truncated pcapng simple packet block.")
            packet_len = struct.unpack(f"{endian}I", body[:4])[0]
            packet_data = body[4 : 4 + min(packet_len, len(body) - 4)]
            linktype = interfaces[0]["linktype"] if interfaces else LINKTYPE_ETHERNET
            records.append(PacketRecord(timestamp=0.0, packet_data=packet_data, wire_len=packet_len, linktype=linktype))

        elif block_type == PCAPNG_BLOCK_PACKET:
            if len(body) < 20:
                raise CaptureFormatError("Truncated pcapng packet block.")
            interface_id, _, ts_high, ts_low, captured_len, packet_len = struct.unpack(f"{endian}HHIIII", body[:20])
            if interface_id >= len(interfaces):
                warnings.append("Encountered an older packet block with an unknown interface.")
            else:
                packet_data = body[20 : 20 + captured_len]
                if len(packet_data) != captured_len:
                    raise CaptureFormatError("Truncated pcapng packet block payload.")
                timestamp_raw = (ts_high << 32) | ts_low
                records.append(
                    PacketRecord(
                        timestamp=timestamp_raw / interfaces[interface_id]["ts_divisor"],
                        packet_data=packet_data,
                        wire_len=packet_len,
                        linktype=interfaces[interface_id]["linktype"],
                    )
                )

        offset += block_total_length

    return records


def parse_ipv4_packet(packet_data: bytes) -> dict[str, object] | None:
    if len(packet_data) < 20:
        return None
    version_ihl = packet_data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or len(packet_data) < ihl:
        return None
    total_length = struct.unpack("!H", packet_data[2:4])[0]
    protocol = packet_data[9]
    src_ip = str(ipaddress.IPv4Address(packet_data[12:16]))
    dst_ip = str(ipaddress.IPv4Address(packet_data[16:20]))
    payload_end = min(len(packet_data), total_length if total_length else len(packet_data))
    return {
        "ip_version": 4,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "payload": packet_data[ihl:payload_end],
    }


def parse_ipv6_packet(packet_data: bytes) -> dict[str, object] | None:
    if len(packet_data) < 40 or packet_data[0] >> 4 != 6:
        return None
    payload_length = struct.unpack("!H", packet_data[4:6])[0]
    next_header = packet_data[6]
    src_ip = str(ipaddress.IPv6Address(packet_data[8:24]))
    dst_ip = str(ipaddress.IPv6Address(packet_data[24:40]))
    payload_end = min(len(packet_data), 40 + payload_length)
    cursor = 40

    while next_header in IPV6_EXTENSION_HEADERS and cursor + 2 <= payload_end:
        current_header = next_header
        if current_header == 44:
            if cursor + 8 > payload_end:
                return None
            next_header = packet_data[cursor]
            cursor += 8
            continue
        if current_header == 51:
            if cursor + 2 > payload_end:
                return None
            next_header = packet_data[cursor]
            extension_length = (packet_data[cursor + 1] + 2) * 4
            if cursor + extension_length > payload_end:
                return None
            cursor += extension_length
            continue
        next_header = packet_data[cursor]
        extension_length = (packet_data[cursor + 1] + 1) * 8
        if cursor + extension_length > payload_end:
            return None
        cursor += extension_length

    return {
        "ip_version": 6,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": next_header,
        "payload": packet_data[cursor:payload_end],
    }


def parse_ethernet_packet(packet_data: bytes) -> dict[str, object] | None:
    if len(packet_data) < 14:
        return None
    ether_type = struct.unpack("!H", packet_data[12:14])[0]
    offset = 14
    while ether_type in ETHERTYPE_VLAN:
        if len(packet_data) < offset + 4:
            return None
        ether_type = struct.unpack("!H", packet_data[offset + 2 : offset + 4])[0]
        offset += 4
    payload = packet_data[offset:]
    if ether_type == ETHERTYPE_IPV4:
        return parse_ipv4_packet(payload)
    if ether_type == ETHERTYPE_IPV6:
        return parse_ipv6_packet(payload)
    return None


def parse_linux_sll_packet(packet_data: bytes) -> dict[str, object] | None:
    if len(packet_data) < 16:
        return None
    protocol = struct.unpack("!H", packet_data[14:16])[0]
    payload = packet_data[16:]
    if protocol == ETHERTYPE_IPV4:
        return parse_ipv4_packet(payload)
    if protocol == ETHERTYPE_IPV6:
        return parse_ipv6_packet(payload)
    return None


def parse_raw_packet(packet_data: bytes) -> dict[str, object] | None:
    if not packet_data:
        return None
    version = packet_data[0] >> 4
    if version == 4:
        return parse_ipv4_packet(packet_data)
    if version == 6:
        return parse_ipv6_packet(packet_data)
    return None


def parse_network_packet(packet_data: bytes, linktype: int) -> dict[str, object] | None:
    if linktype == LINKTYPE_ETHERNET:
        return parse_ethernet_packet(packet_data)
    if linktype == LINKTYPE_RAW:
        return parse_raw_packet(packet_data)
    if linktype == LINKTYPE_LINUX_SLL:
        return parse_linux_sll_packet(packet_data)
    if linktype == LINKTYPE_NULL:
        return parse_raw_packet(packet_data[4:]) if len(packet_data) > 4 else None
    return None


class PcapAnalyzer:
    def __init__(self, external_lookup_config: dict[str, object] | None = None) -> None:
        self.capture_format = "unknown"
        self.capture_sha256 = ""
        self.packet_count = 0
        self.total_bytes = 0
        self.unsupported_packets = 0
        self.layer4_counter: Counter[str] = Counter()
        self.app_counter: Counter[str] = Counter()
        self.port_counter: Counter[int] = Counter()
        self.flows: dict[FlowKey, FlowStats] = {}
        self.hosts: dict[str, HostStats] = defaultdict(HostStats)
        self.dns_queries: list[dict[str, object]] = []
        self.http_events: list[dict[str, object]] = []
        self.tls_events: list[dict[str, object]] = []
        self.kerberos_events: list[dict[str, object]] = []
        self.ldap_events: list[dict[str, object]] = []
        self.smb_events: list[dict[str, object]] = []
        self.rpc_events: list[dict[str, object]] = []
        self.syn_tracker: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
        self.directory_server_ports: dict[str, set[int]] = defaultdict(set)
        self.directory_server_clients: dict[str, set[str]] = defaultdict(set)
        self.tcp_streams: dict[tuple[tuple[str, int], tuple[str, int]], dict[str, object]] = {}
        self.extracted_artifacts: list[dict[str, object]] = []
        self.threat_intel_matches: list[dict[str, object]] = []
        self.important_frames: list[dict[str, object]] = []
        self.timeline_events: list[dict[str, object]] = []
        self.suspicious_hosts: dict[str, dict[str, object]] = defaultdict(lambda: {"score": 0, "evidence": []})
        self.local_intel = load_local_intel()
        self.external_lookup_config = normalize_external_lookup_config(external_lookup_config)
        self.external_intel: dict[str, object] = {
            "requested": False,
            "enabled": False,
            "providers": [],
            "items": [],
            "warnings": [],
            "summary": {"lookup_count": 0, "high": 0, "medium": 0, "low": 0},
        }
        self.linktypes_seen: set[int] = set()
        self.timestamps: list[float] = []
        self.warnings: list[str] = []

    def analyze_path(self, path: pathlib.Path) -> dict[str, object]:
        return self.analyze_bytes(path.read_bytes(), source_name=str(path))

    def analyze_bytes(self, data: bytes, source_name: str = "<memory>") -> dict[str, object]:
        self.capture_sha256 = sha256_hex(data)
        self.capture_format = detect_capture_format(data)
        if self.capture_format == "pcap":
            records = parse_pcap_records(data)
        else:
            records = parse_pcapng_records(data, self.warnings)

        if not records:
            raise CaptureFormatError("Capture did not contain any packets.")

        for packet_index, record in enumerate(records, start=1):
            self.packet_count += 1
            self.total_bytes += record.wire_len
            self.linktypes_seen.add(record.linktype)
            if record.timestamp > 0:
                self.timestamps.append(record.timestamp)
            self._analyze_packet(record, packet_index)

        self._extract_artifacts_from_streams()
        self._run_external_enrichment()
        detections = self._run_detections()
        self._finalize_host_scores(detections)
        self._finalize_timeline(detections)
        return self._build_report(source_name, detections)

    def _mark_directory_activity(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> None:
        if dst_port in AD_DISCOVERY_PORTS and is_private_ip(dst_ip):
            self.directory_server_ports[dst_ip].add(dst_port)
            self.directory_server_clients[dst_ip].add(src_ip)
        if src_port in AD_DISCOVERY_PORTS and is_private_ip(src_ip):
            self.directory_server_ports[src_ip].add(src_port)
            self.directory_server_clients[src_ip].add(dst_ip)

    def _record_important_frame(
        self,
        packet_index: int,
        timestamp: float,
        summary: str,
        severity: str = "info",
        src_ip: str = "",
        dst_ip: str = "",
        protocol: str = "",
        packet_meta: dict[str, object] | None = None,
    ) -> None:
        self.important_frames.append(
            {
                "packet_index": packet_index,
                "timestamp": round(timestamp, 6),
                "summary": summary,
                "severity": severity,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "packet_meta": packet_meta or {},
            }
        )

    def _add_timeline_event(
        self,
        timestamp: float,
        category: str,
        summary: str,
        severity: str = "info",
        host_ip: str = "",
        peer_ip: str = "",
        packet_index: int | None = None,
    ) -> None:
        self.timeline_events.append(
            {
                "timestamp": round(timestamp, 6),
                "category": category,
                "summary": summary,
                "severity": severity,
                "host_ip": host_ip,
                "peer_ip": peer_ip,
                "packet_index": packet_index,
            }
        )

    def _mark_suspicious_host(self, host_ip: str, score: int, evidence: str) -> None:
        if not host_ip:
            return
        self.suspicious_hosts[host_ip]["score"] += score
        if evidence not in self.suspicious_hosts[host_ip]["evidence"]:
            self.suspicious_hosts[host_ip]["evidence"].append(evidence)

    def _tcp_connection_key(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int
    ) -> tuple[tuple[str, int], tuple[str, int]]:
        left = (src_ip, src_port)
        right = (dst_ip, dst_port)
        return (left, right) if left <= right else (right, left)

    def _track_tcp_segment(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        seq: int,
        payload: bytes,
        packet_index: int,
        timestamp: float,
    ) -> None:
        if not payload:
            return
        connection_key = self._tcp_connection_key(src_ip, src_port, dst_ip, dst_port)
        stream = self.tcp_streams.setdefault(
            connection_key,
            {
                "endpoints": connection_key,
                "directions": defaultdict(list),
            },
        )
        direction_key = (src_ip, src_port, dst_ip, dst_port)
        stream["directions"][direction_key].append(
            {
                "seq": seq,
                "payload": payload,
                "packet_index": packet_index,
                "timestamp": timestamp,
            }
        )

    def _analyze_packet(self, record: PacketRecord, packet_index: int) -> None:
        parsed = parse_network_packet(record.packet_data, record.linktype)
        if not parsed:
            self.unsupported_packets += 1
            warning = f"Unsupported or non-IP packet encountered on {linktype_name(record.linktype)}."
            if warning not in self.warnings:
                self.warnings.append(warning)
            return

        src_ip = str(parsed["src_ip"])
        dst_ip = str(parsed["dst_ip"])
        protocol = int(parsed["protocol"])
        payload = bytes(parsed["payload"])

        self.hosts[src_ip].packets_sent += 1
        self.hosts[src_ip].bytes_sent += record.wire_len
        self.hosts[src_ip].peers.add(dst_ip)
        self.hosts[dst_ip].packets_received += 1
        self.hosts[dst_ip].bytes_received += record.wire_len
        self.hosts[dst_ip].peers.add(src_ip)

        if protocol == 6:
            self.layer4_counter["TCP"] += 1
            tcp = self._parse_tcp(payload)
            if not tcp:
                self.unsupported_packets += 1
                return
            self._track_tcp_segment(
                src_ip,
                tcp["src_port"],
                dst_ip,
                tcp["dst_port"],
                int(tcp["seq"]),
                bytes(tcp["payload"]),
                packet_index,
                record.timestamp,
            )
            flow_key = FlowKey(src_ip, dst_ip, tcp["src_port"], tcp["dst_port"], "TCP")
            flow = self.flows.setdefault(flow_key, FlowStats())
            flow.observe(record.timestamp, record.wire_len, len(tcp["payload"]), tcp["flags"])
            self.port_counter[tcp["dst_port"]] += 1
            self._mark_directory_activity(src_ip, dst_ip, tcp["src_port"], tcp["dst_port"])

            if tcp["flags"] & TCP_SYN and not (tcp["flags"] & TCP_ACK):
                self.syn_tracker[src_ip][dst_ip].add(tcp["dst_port"])

            http = parse_http_payload(tcp["payload"])
            if http:
                flow.app_protocols["HTTP"] += 1
                self.app_counter["HTTP"] += 1
                self.http_events.append({"src_ip": src_ip, "dst_ip": dst_ip, "packet_index": packet_index, **http})
                if http.get("kind") == "request":
                    self._record_important_frame(
                        packet_index,
                        record.timestamp,
                        f"HTTP request {http.get('method', 'GET')} {http.get('host', dst_ip)}{http.get('path', '')}",
                        severity="info",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol="HTTP",
                    )
                    request_host = str(http.get("host") or dst_ip)
                    self._add_timeline_event(
                        record.timestamp,
                        "http",
                        f"HTTP request {http.get('method', 'GET')} to {request_host}{http.get('path', '')}",
                        severity="medium" if not is_private_ip(dst_ip) else "info",
                        host_ip=src_ip,
                        peer_ip=dst_ip,
                        packet_index=packet_index,
                    )

            tls = parse_tls_client_hello(tcp["payload"])
            if tls:
                flow.app_protocols["TLS"] += 1
                self.app_counter["TLS"] += 1
                self.tls_events.append({"src_ip": src_ip, "dst_ip": dst_ip, "packet_index": packet_index, **tls})

            if tcp["src_port"] in KERBEROS_PORTS or tcp["dst_port"] in KERBEROS_PORTS:
                kerberos = parse_kerberos_message(tcp["payload"])
                if kerberos:
                    flow.app_protocols["Kerberos"] += 1
                    self.app_counter["Kerberos"] += 1
                    server_ip = dst_ip if tcp["dst_port"] in KERBEROS_PORTS else src_ip
                    client_ip = src_ip if server_ip == dst_ip else dst_ip
                    self.kerberos_events.append(
                        {
                            "timestamp": round(record.timestamp, 6),
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "client_ip": client_ip,
                            "server_ip": server_ip,
                            "packet_index": packet_index,
                            "transport": "TCP",
                            **kerberos,
                        }
                    )
                    self._record_important_frame(
                        packet_index,
                        record.timestamp,
                        f"Kerberos {kerberos['message_name']} between {client_ip} and {server_ip}",
                        severity="medium" if kerberos["message_name"] in {"TGS-REQ", "AS-REQ"} else "info",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol="Kerberos",
                    )
                    if kerberos["message_name"] in {"TGS-REQ", "AS-REQ", "AS-REP", "TGS-REP"}:
                        ticket_target = ", ".join(kerberos.get("token_sample", [])[:2])
                        self._add_timeline_event(
                            record.timestamp,
                            "kerberos",
                            f"{kerberos['message_name']} {ticket_target}".strip(),
                            severity="medium" if kerberos["message_name"] in {"TGS-REQ", "AS-REQ"} else "info",
                            host_ip=client_ip,
                            peer_ip=server_ip,
                            packet_index=packet_index,
                        )

            if tcp["src_port"] in LDAP_PORTS | LDAPS_PORTS or tcp["dst_port"] in LDAP_PORTS | LDAPS_PORTS:
                server_port = tcp["dst_port"] if tcp["dst_port"] in LDAP_PORTS | LDAPS_PORTS else tcp["src_port"]
                server_ip = dst_ip if tcp["dst_port"] in LDAP_PORTS | LDAPS_PORTS else src_ip
                client_ip = src_ip if server_ip == dst_ip else dst_ip
                if server_port in LDAP_PORTS:
                    ldap = parse_ldap_message(tcp["payload"])
                    if ldap:
                        flow.app_protocols["LDAP"] += 1
                        self.app_counter["LDAP"] += 1
                        self.ldap_events.append(
                            {
                                "timestamp": round(record.timestamp, 6),
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "client_ip": client_ip,
                                "server_ip": server_ip,
                                "packet_index": packet_index,
                                "transport": "TCP",
                                **ldap,
                            }
                        )
                        if ldap.get("delegation_keywords"):
                            self._record_important_frame(
                                packet_index,
                                record.timestamp,
                                f"LDAP delegation-related query from {client_ip} to {server_ip}",
                                severity="high",
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                protocol="LDAP",
                            )
                            self._add_timeline_event(
                                record.timestamp,
                                "ldap",
                                f"Delegation-related LDAP query from {client_ip} to {server_ip}",
                                severity="high",
                                host_ip=client_ip,
                                peer_ip=server_ip,
                                packet_index=packet_index,
                            )
                elif tcp["payload"]:
                    flow.app_protocols["LDAPS"] += 1
                    self.app_counter["LDAPS"] += 1

            if tcp["src_port"] in SMB_PORTS or tcp["dst_port"] in SMB_PORTS:
                smb = parse_smb_message(tcp["payload"])
                if smb:
                    flow.app_protocols["SMB"] += 1
                    self.app_counter["SMB"] += 1
                    server_ip = dst_ip if tcp["dst_port"] in SMB_PORTS else src_ip
                    client_ip = src_ip if server_ip == dst_ip else dst_ip
                    self.smb_events.append(
                        {
                            "timestamp": round(record.timestamp, 6),
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "client_ip": client_ip,
                            "server_ip": server_ip,
                            "packet_index": packet_index,
                            **smb,
                        }
                    )

            if tcp["src_port"] in RPC_PORTS or tcp["dst_port"] in RPC_PORTS or DRSUAPI_UUID_BYTES in tcp["payload"]:
                rpc = parse_dce_rpc_message(tcp["payload"])
                if rpc:
                    flow.app_protocols["RPC"] += 1
                    self.app_counter["RPC"] += 1
                    if tcp["src_port"] in RPC_PORTS or tcp["src_port"] in SMB_PORTS:
                        server_ip = src_ip
                        client_ip = dst_ip
                    else:
                        server_ip = dst_ip
                        client_ip = src_ip
                    self.rpc_events.append(
                        {
                            "timestamp": round(record.timestamp, 6),
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "client_ip": client_ip,
                            "server_ip": server_ip,
                            "packet_index": packet_index,
                            **rpc,
                        }
                    )
                    if rpc.get("contains_drsuapi"):
                        self._record_important_frame(
                            packet_index,
                            record.timestamp,
                            f"DRSUAPI replication interface traffic from {client_ip} to {server_ip}",
                            severity="high",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            protocol="RPC",
                        )
                        self._add_timeline_event(
                            record.timestamp,
                            "rpc",
                            f"DRSUAPI replication traffic from {client_ip} to {server_ip}",
                            severity="high",
                            host_ip=client_ip,
                            peer_ip=server_ip,
                            packet_index=packet_index,
                        )

        elif protocol == 17:
            self.layer4_counter["UDP"] += 1
            udp = self._parse_udp(payload)
            if not udp:
                self.unsupported_packets += 1
                return
            flow_key = FlowKey(src_ip, dst_ip, udp["src_port"], udp["dst_port"], "UDP")
            flow = self.flows.setdefault(flow_key, FlowStats())
            flow.observe(record.timestamp, record.wire_len, len(udp["payload"]))
            self.port_counter[udp["dst_port"]] += 1
            self._mark_directory_activity(src_ip, dst_ip, udp["src_port"], udp["dst_port"])

            if udp["src_port"] == 53 or udp["dst_port"] == 53:
                dns = parse_dns_message(udp["payload"])
                if dns:
                    flow.app_protocols["DNS"] += 1
                    self.app_counter["DNS"] += 1
                    for question in dns["questions"]:
                        self.dns_queries.append(
                            {
                                "timestamp": round(record.timestamp, 6),
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "packet_index": packet_index,
                                "query": question,
                                "is_response": dns["is_response"],
                                "rcode": dns["rcode"],
                            }
                        )
                        if not dns["is_response"] and len(question.split(".")) >= 3:
                            self._record_important_frame(
                                packet_index,
                                record.timestamp,
                                f"DNS query {question}",
                                severity="info",
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                protocol="DNS",
                            )
                            first_label = question.split(".", 1)[0]
                            severity = "medium" if len(first_label) >= 18 or shannon_entropy(first_label) >= 4.1 else "info"
                            self._add_timeline_event(
                                record.timestamp,
                                "dns",
                                f"DNS query {question}",
                                severity=severity,
                                host_ip=src_ip,
                                peer_ip=dst_ip,
                                packet_index=packet_index,
                            )

            if udp["src_port"] in KERBEROS_PORTS or udp["dst_port"] in KERBEROS_PORTS:
                kerberos = parse_kerberos_message(udp["payload"])
                if kerberos:
                    flow.app_protocols["Kerberos"] += 1
                    self.app_counter["Kerberos"] += 1
                    server_ip = dst_ip if udp["dst_port"] in KERBEROS_PORTS else src_ip
                    client_ip = src_ip if server_ip == dst_ip else dst_ip
                    self.kerberos_events.append(
                        {
                            "timestamp": round(record.timestamp, 6),
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "client_ip": client_ip,
                            "server_ip": server_ip,
                            "packet_index": packet_index,
                            "transport": "UDP",
                            **kerberos,
                        }
                    )

        elif protocol == 1:
            self.layer4_counter["ICMP"] += 1
        elif protocol == 58:
            self.layer4_counter["ICMPv6"] += 1
        else:
            self.layer4_counter[f"IP_{protocol}"] += 1

    def _parse_tcp(self, payload: bytes) -> dict[str, object] | None:
        if len(payload) < 20:
            return None
        src_port, dst_port, seq, ack, offset_reserved, flags, _, _, _ = struct.unpack("!HHIIBBHHH", payload[:20])
        data_offset = (offset_reserved >> 4) * 4
        if len(payload) < data_offset:
            return None
        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "seq": seq,
            "ack": ack,
            "flags": flags,
            "payload": payload[data_offset:],
        }

    def _parse_udp(self, payload: bytes) -> dict[str, object] | None:
        if len(payload) < 8:
            return None
        src_port, dst_port, length, _ = struct.unpack("!HHHH", payload[:8])
        udp_payload = payload[8:length] if length >= 8 else b""
        return {"src_port": src_port, "dst_port": dst_port, "payload": udp_payload}

    def _reassemble_segments(self, segments: list[dict[str, object]]) -> tuple[bytes, list[int]]:
        if not segments:
            return b"", []
        ordered = sorted(segments, key=lambda item: (int(item["seq"]), int(item["packet_index"])))
        output = bytearray()
        packet_indexes: list[int] = []
        cursor = None
        for segment in ordered:
            seq = int(segment["seq"])
            payload = bytes(segment["payload"])
            if cursor is None:
                output.extend(payload)
                packet_indexes.append(int(segment["packet_index"]))
                cursor = seq + len(payload)
                continue
            if seq > cursor:
                output.extend(payload)
                packet_indexes.append(int(segment["packet_index"]))
                cursor = seq + len(payload)
                continue
            overlap = cursor - seq
            if overlap < len(payload):
                output.extend(payload[overlap:])
                packet_indexes.append(int(segment["packet_index"]))
                cursor += len(payload) - overlap
        return bytes(output), packet_indexes

    def _match_local_intel(
        self,
        artifact_sha256: str,
        filename: str,
        request_host: str,
    ) -> list[dict[str, object]]:
        matches: list[dict[str, object]] = []
        hash_entry = self.local_intel["hashes"].get(artifact_sha256)
        if isinstance(hash_entry, dict):
            matches.append({"match_type": "sha256", **hash_entry, "sha256": artifact_sha256})
        elif isinstance(hash_entry, str):
            matches.append({"match_type": "sha256", "name": hash_entry, "sha256": artifact_sha256})

        filename_entry = self.local_intel["filenames"].get(filename.lower()) if filename else None
        if isinstance(filename_entry, dict):
            matches.append({"match_type": "filename", **filename_entry, "filename": filename})
        elif isinstance(filename_entry, str):
            matches.append({"match_type": "filename", "name": filename_entry, "filename": filename})

        domain_entry = self.local_intel["domains"].get(request_host.lower()) if request_host else None
        if isinstance(domain_entry, dict):
            matches.append({"match_type": "domain", **domain_entry, "domain": request_host})
        elif isinstance(domain_entry, str):
            matches.append({"match_type": "domain", "name": domain_entry, "domain": request_host})
        return matches

    def _extract_artifacts_from_streams(self) -> None:
        for connection_key, stream in self.tcp_streams.items():
            directions: dict[tuple[str, int, str, int], list[dict[str, object]]] = stream["directions"]
            if len(directions) < 2:
                continue
            endpoints = list(connection_key)
            client_to_server = None
            server_to_client = None
            for direction_key in directions:
                if direction_key[1] > direction_key[3]:
                    client_to_server = direction_key
                elif client_to_server is None:
                    client_to_server = direction_key
            for direction_key in directions:
                if direction_key != client_to_server:
                    server_to_client = direction_key
                    break
            if client_to_server is None or server_to_client is None:
                continue
            client_stream, request_packet_indexes = self._reassemble_segments(directions[client_to_server])
            server_stream, response_packet_indexes = self._reassemble_segments(directions[server_to_client])
            requests = scan_http_requests(client_stream)
            responses = scan_http_responses(server_stream)
            if not requests or not responses:
                continue
            for index, response in enumerate(responses):
                request = requests[min(index, len(requests) - 1)]
                filename = ""
                disposition = response["headers"].get("content-disposition", "")
                if "filename=" in disposition:
                    filename = disposition.split("filename=", 1)[1].strip().strip('"')
                if not filename:
                    filename = pathlib.PurePosixPath(str(request.get("path", ""))).name
                body = bytes(response["body"])
                artifact_type, suspicious = guess_artifact_type(body, response["headers"], str(request.get("path", "")))
                if not body or (not suspicious and len(body) < 256):
                    continue
                artifact_sha = sha256_hex(body)
                intel_matches = self._match_local_intel(artifact_sha, filename, str(request.get("host", "")))
                artifact = {
                    "sha256": artifact_sha,
                    "size": len(body),
                    "filename": filename or f"artifact_{len(self.extracted_artifacts) + 1}.bin",
                    "type": artifact_type,
                    "suspicious": suspicious,
                    "complete": response["complete"],
                    "request_host": request.get("host", ""),
                    "request_path": request.get("path", ""),
                    "source_ip": server_to_client[0],
                    "destination_ip": server_to_client[2],
                    "packet_indexes": response_packet_indexes[:8],
                    "intel_matches": intel_matches,
                }
                self.extracted_artifacts.append(artifact)
                if intel_matches:
                    for match in intel_matches:
                        self.threat_intel_matches.append(
                            {
                                "artifact_sha256": artifact_sha,
                                "filename": artifact["filename"],
                                "source_ip": artifact["source_ip"],
                                "destination_ip": artifact["destination_ip"],
                                **match,
                            }
                        )
                severity = "high" if intel_matches else "medium" if suspicious else "info"
                packet_index = int(response_packet_indexes[0]) if response_packet_indexes else None
                if packet_index is not None:
                    self._record_important_frame(
                        packet_index,
                        directions[server_to_client][0]["timestamp"],
                        f"Recovered HTTP artifact {artifact['filename']} ({artifact_type})",
                        severity=severity,
                        src_ip=artifact["source_ip"],
                        dst_ip=artifact["destination_ip"],
                        protocol="HTTP",
                        packet_meta={"sha256": artifact_sha},
                    )
                self._add_timeline_event(
                    directions[server_to_client][0]["timestamp"],
                    "artifact",
                    f"Recovered {artifact['filename']} from {artifact['request_host'] or artifact['source_ip']}",
                    severity=severity,
                    host_ip=artifact["destination_ip"],
                    peer_ip=artifact["source_ip"],
                    packet_index=packet_index,
                )
                self._mark_suspicious_host(
                    artifact["destination_ip"],
                    30 if intel_matches else 18 if suspicious else 8,
                    f"Downloaded artifact {artifact['filename']} ({artifact_type}, sha256 {artifact_sha[:12]}...)",
                )

    def _build_external_artifact_inputs(self) -> list[dict[str, object]]:
        deduped: dict[str, dict[str, object]] = {}
        for artifact in self.extracted_artifacts:
            sha256 = str(artifact.get("sha256", ""))
            if not sha256:
                continue
            deduped.setdefault(sha256, artifact)
        return list(deduped.values())

    def _build_external_domain_inputs(self) -> list[dict[str, object]]:
        ranked: dict[str, dict[str, object]] = {}

        for event in self.http_events:
            if event.get("kind") != "request":
                continue
            domain = str(event.get("host", "")).strip().lower()
            if not domain:
                continue
            entry = ranked.setdefault(
                domain,
                {
                    "domain": domain,
                    "host_ip": str(event.get("src_ip", "")),
                    "peer_ip": str(event.get("dst_ip", "")),
                    "source": "http",
                    "score": 0,
                },
            )
            entry["score"] += 3 if not is_private_ip(str(event.get("dst_ip", ""))) else 1

        for query in self.dns_queries:
            if query.get("is_response"):
                continue
            domain = registered_domain(str(query.get("query", "")).strip().lower())
            if not domain:
                continue
            entry = ranked.setdefault(
                domain,
                {
                    "domain": domain,
                    "host_ip": str(query.get("src_ip", "")),
                    "peer_ip": str(query.get("dst_ip", "")),
                    "source": "dns",
                    "score": 0,
                },
            )
            label = str(query.get("query", "")).split(".", 1)[0]
            entry["score"] += 3 if len(label) >= 18 or shannon_entropy(label) >= 4.1 else 1

        return [
            {key: value for key, value in item.items() if key != "score"}
            for item in sorted(ranked.values(), key=lambda value: int(value["score"]), reverse=True)
        ]

    def _run_external_enrichment(self) -> None:
        if not bool(self.external_lookup_config.get("enabled")):
            return
        external_intel = run_external_enrichment(
            self._build_external_artifact_inputs(),
            self._build_external_domain_inputs(),
            self.external_lookup_config,
        )
        self.external_intel = external_intel
        for warning in external_intel.get("warnings", []):
            text = str(warning)
            if text and text not in self.warnings:
                self.warnings.append(text)

    def _finalize_host_scores(self, detections: list[Detection]) -> None:
        severity_weights = {"high": 26, "medium": 14, "low": 6}
        for detection in detections:
            details = detection.details
            if detection.name in {"suspicious_artifact_delivery", "local_intel_match"}:
                impacted_host = str(details.get("destination_ip", ""))
                delivery_source = str(details.get("source_ip", ""))
                if impacted_host:
                    self._mark_suspicious_host(
                        impacted_host,
                        severity_weights.get(detection.severity, 4),
                        detection.summary,
                    )
                if delivery_source and is_private_ip(delivery_source):
                    self._mark_suspicious_host(
                        delivery_source,
                        max(4, severity_weights.get(detection.severity, 4) // 2),
                        detection.summary,
                    )
                continue
            for key in ("source_ip", "client_ip", "host_ip"):
                value = str(details.get(key, ""))
                if value:
                    self._mark_suspicious_host(value, severity_weights.get(detection.severity, 4), detection.summary)
            for key in ("destination_ip", "directory_server", "kdc"):
                value = str(details.get(key, ""))
                if value and is_private_ip(value):
                    self._mark_suspicious_host(value, max(4, severity_weights.get(detection.severity, 4) // 3), detection.summary)

        for event in self.http_events:
            if event.get("kind") == "request" and not is_private_ip(str(event["dst_ip"])):
                self._mark_suspicious_host(str(event["src_ip"]), 4, f"Reached external HTTP host {event.get('host') or event['dst_ip']}")

        for entry in self.kerberos_events:
            if entry.get("message_name") == "TGS-REQ":
                self._mark_suspicious_host(str(entry["client_ip"]), 2, "Requested Kerberos service tickets")
        for entry in self.ldap_events:
            if entry.get("delegation_keywords"):
                self._mark_suspicious_host(str(entry["client_ip"]), 10, "Queried LDAP delegation-related attributes")

    def _estimate_detection_timestamp(
        self,
        host_ip: str,
        peer_ip: str,
        packet_index: int | None = None,
    ) -> tuple[float, int | None]:
        if packet_index is not None:
            for frame in self.important_frames:
                if int(frame["packet_index"]) == packet_index:
                    return float(frame["timestamp"]), int(frame["packet_index"])

        matching_frames = [
            frame
            for frame in self.important_frames
            if (
                (host_ip and host_ip in {str(frame.get("src_ip", "")), str(frame.get("dst_ip", ""))})
                or (peer_ip and peer_ip in {str(frame.get("src_ip", "")), str(frame.get("dst_ip", ""))})
            )
        ]
        if matching_frames:
            first = min(matching_frames, key=lambda item: (float(item["timestamp"]), int(item["packet_index"])))
            return float(first["timestamp"]), int(first["packet_index"])

        matching_events = [
            event
            for event in self.timeline_events
            if (
                (host_ip and host_ip in {str(event.get("host_ip", "")), str(event.get("peer_ip", ""))})
                or (peer_ip and peer_ip in {str(event.get("host_ip", "")), str(event.get("peer_ip", ""))})
            )
        ]
        if matching_events:
            first = min(matching_events, key=lambda item: float(item["timestamp"]))
            return float(first["timestamp"]), int(first["packet_index"]) if first.get("packet_index") is not None else None

        return (self.timestamps[0] if self.timestamps else 0.0), packet_index

    def _finalize_timeline(self, detections: list[Detection]) -> None:
        for detection in detections:
            details = detection.details
            host_ip = str(details.get("source_ip") or details.get("client_ip") or "")
            peer_ip = str(details.get("destination_ip") or details.get("directory_server") or details.get("kdc") or "")
            packet_index = details.get("packet_index")
            if isinstance(packet_index, list):
                packet_index = packet_index[0] if packet_index else None
            timestamp, resolved_packet_index = self._estimate_detection_timestamp(
                host_ip,
                peer_ip,
                int(packet_index) if isinstance(packet_index, int) else None,
            )
            self._add_timeline_event(
                timestamp,
                "detection",
                detection.summary,
                severity=detection.severity,
                host_ip=host_ip,
                peer_ip=peer_ip,
                packet_index=resolved_packet_index,
            )
        self.timeline_events = sorted(self.timeline_events, key=lambda item: (float(item["timestamp"]), str(item["category"])))[:MAX_TIMELINE_EVENTS]
        self.important_frames = sorted(self.important_frames, key=lambda item: int(item["packet_index"]))[:40]

    def _run_detections(self) -> list[Detection]:
        detections: list[Detection] = []
        detections.extend(self._detect_syn_scans())
        detections.extend(self._detect_dns_anomalies())
        detections.extend(self._detect_beacons())
        detections.extend(self._detect_cleartext_http())
        detections.extend(self._detect_uncommon_external_ports())
        detections.extend(self._detect_delegation_enumeration())
        detections.extend(self._detect_ldap_reconnaissance())
        detections.extend(self._detect_kerberoasting())
        detections.extend(self._detect_asreq_sweeps())
        detections.extend(self._detect_dcsync_like_activity())
        detections.extend(self._detect_suspicious_artifacts())
        detections.extend(self._detect_local_intel_matches())
        detections.extend(self._detect_external_intel_hits())
        return sorted(
            detections,
            key=lambda item: ({"high": 0, "medium": 1, "low": 2}.get(item.severity, 3), item.name),
        )

    def _likely_directory_servers(self) -> list[dict[str, object]]:
        candidates: list[dict[str, object]] = []
        for host, ports in self.directory_server_ports.items():
            if not is_private_ip(host):
                continue
            client_count = len(self.directory_server_clients.get(host, set()))
            score = (len(ports) * 3) + (client_count * 2)
            if 88 in ports:
                score += 2
            if 389 in ports or 3268 in ports:
                score += 2
            if len(ports) >= 2 or client_count >= 2:
                candidates.append(
                    {
                        "ip": host,
                        "ports": sorted(ports),
                        "client_count": client_count,
                        "score": score,
                    }
                )
        return sorted(candidates, key=lambda item: item["score"], reverse=True)[:8]

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

    def _detect_cleartext_http(self) -> list[Detection]:
        detections: list[Detection] = []
        seen: set[tuple[str, str, str, str]] = set()
        for event in self.http_events:
            if event.get("kind") != "request":
                continue
            src_ip = str(event["src_ip"])
            dst_ip = str(event["dst_ip"])
            if not is_private_ip(src_ip) or is_private_ip(dst_ip):
                continue
            key = (src_ip, dst_ip, str(event.get("host", "")), str(event.get("path", "")))
            if key in seen:
                continue
            seen.add(key)
            detections.append(
                Detection(
                    severity="low",
                    name="cleartext_http_external",
                    summary=f"Cleartext HTTP request from {src_ip} to external host {dst_ip}.",
                    details={
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "host": event.get("host", ""),
                        "path": event.get("path", ""),
                    },
                )
            )
        return detections

    def _detect_uncommon_external_ports(self) -> list[Detection]:
        detections: list[Detection] = []
        for flow_key, flow in self.flows.items():
            if (
                flow_key.protocol == "TCP"
                and is_private_ip(flow_key.src_ip)
                and not is_private_ip(flow_key.dst_ip)
                and flow_key.dst_port not in COMMON_PORTS
                and flow.packets >= 5
            ):
                detections.append(
                    Detection(
                        severity="low",
                        name="uncommon_external_tcp_port",
                        summary=f"{flow_key.src_ip} maintained external TCP traffic to uncommon port {flow_key.dst_port}.",
                        details={
                            "source_ip": flow_key.src_ip,
                            "destination_ip": flow_key.dst_ip,
                            "destination_port": flow_key.dst_port,
                            "packet_count": flow.packets,
                        },
                    )
                )
        return detections

    def _detect_delegation_enumeration(self) -> list[Detection]:
        grouped: dict[tuple[str, str], set[str]] = defaultdict(set)
        counts: Counter[tuple[str, str]] = Counter()
        for event in self.ldap_events:
            keywords = event.get("delegation_keywords", [])
            if not keywords:
                continue
            key = (str(event["client_ip"]), str(event["server_ip"]))
            grouped[key].update(str(keyword) for keyword in keywords)
            counts[key] += 1

        detections: list[Detection] = []
        for (client_ip, server_ip), keywords in grouped.items():
            detections.append(
                Detection(
                    severity="high" if len(keywords) >= 2 or counts[(client_ip, server_ip)] >= 2 else "medium",
                    name="ad_delegation_enumeration",
                    summary=f"{client_ip} queried LDAP delegation-related attributes on {server_ip}.",
                    details={
                        "source_ip": client_ip,
                        "directory_server": server_ip,
                        "query_count": counts[(client_ip, server_ip)],
                        "keywords": sorted(keywords),
                    },
                )
            )
        return detections

    def _detect_ldap_reconnaissance(self) -> list[Detection]:
        grouped: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        for event in self.ldap_events:
            if str(event.get("operation")) != "SearchRequest":
                continue
            key = (str(event["client_ip"]), str(event["server_ip"]))
            grouped[key]["search_count"] += 1
            for keyword in event.get("keywords", []):
                grouped[key][str(keyword)] += 1

        detections: list[Detection] = []
        for (client_ip, server_ip), counters in grouped.items():
            search_count = counters.pop("search_count", 0)
            if search_count >= 8 or len(counters) >= 3:
                interesting_terms = [term for term, _ in counters.most_common(5)]
                detections.append(
                    Detection(
                        severity="medium",
                        name="ldap_directory_reconnaissance",
                        summary=f"{client_ip} generated a burst of LDAP search traffic against {server_ip}.",
                        details={
                            "source_ip": client_ip,
                            "directory_server": server_ip,
                            "search_count": search_count,
                            "interesting_terms": interesting_terms,
                        },
                    )
                )
        return detections

    def _detect_kerberoasting(self) -> list[Detection]:
        grouped: dict[tuple[str, str], dict[str, object]] = defaultdict(lambda: {"count": 0, "tokens": set()})
        for event in self.kerberos_events:
            if str(event.get("message_name")) != "TGS-REQ":
                continue
            key = (str(event["client_ip"]), str(event["server_ip"]))
            grouped[key]["count"] += 1
            grouped[key]["tokens"].update(str(token) for token in event.get("token_sample", []))

        detections: list[Detection] = []
        for (client_ip, server_ip), data in grouped.items():
            count = int(data["count"])
            tokens = sorted(str(token) for token in data["tokens"])
            if count >= 6:
                detections.append(
                    Detection(
                        severity="high" if count >= 10 else "medium",
                        name="kerberoasting_suspected",
                        summary=f"{client_ip} requested many Kerberos service tickets from {server_ip}.",
                        details={
                            "source_ip": client_ip,
                            "kdc": server_ip,
                            "tgs_request_count": count,
                            "service_tokens": tokens[:6],
                        },
                    )
                )
        return detections

    def _detect_asreq_sweeps(self) -> list[Detection]:
        request_counts: Counter[tuple[str, str]] = Counter()
        error_counts: Counter[tuple[str, str]] = Counter()
        for event in self.kerberos_events:
            key = (str(event["client_ip"]), str(event["server_ip"]))
            if str(event.get("message_name")) == "AS-REQ":
                request_counts[key] += 1
            elif str(event.get("message_name")) == "KRB-ERROR":
                error_counts[key] += 1

        detections: list[Detection] = []
        for key, count in request_counts.items():
            if count >= 6:
                detections.append(
                    Detection(
                        severity="medium",
                        name="bulk_asreq_activity",
                        summary=f"{key[0]} generated repeated AS-REQ traffic to {key[1]}.",
                        details={
                            "source_ip": key[0],
                            "kdc": key[1],
                            "as_req_count": count,
                            "error_count": error_counts.get(key, 0),
                        },
                    )
                )
        return detections

    def _detect_dcsync_like_activity(self) -> list[Detection]:
        grouped: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        likely_servers = {entry["ip"] for entry in self._likely_directory_servers()}
        for event in self.rpc_events:
            if not event.get("contains_drsuapi"):
                continue
            key = (str(event["client_ip"]), str(event["server_ip"]))
            grouped[key][str(event.get("packet_type", "unknown"))] += 1

        detections: list[Detection] = []
        for (client_ip, server_ip), packet_types in grouped.items():
            severity = "high" if not likely_servers or client_ip not in likely_servers else "medium"
            detections.append(
                Detection(
                    severity=severity,
                    name="dcsync_like_rpc",
                    summary=f"{client_ip} accessed the DRSUAPI replication interface on {server_ip}.",
                    details={
                        "source_ip": client_ip,
                        "directory_server": server_ip,
                        "rpc_packets": sum(packet_types.values()),
                        "packet_types": dict(packet_types),
                    },
                )
            )
        return detections

    def _detect_suspicious_artifacts(self) -> list[Detection]:
        detections: list[Detection] = []
        for artifact in self.extracted_artifacts:
            suspicious = bool(artifact.get("suspicious"))
            intel_matches = list(artifact.get("intel_matches", []))
            if not suspicious and not intel_matches:
                continue
            severity = "high" if intel_matches else "medium"
            detections.append(
                Detection(
                    severity=severity,
                    name="suspicious_artifact_delivery",
                    summary=(
                        f"Recovered {artifact['filename']} ({artifact['type']}) delivered from "
                        f"{artifact['source_ip']} to {artifact['destination_ip']}."
                    ),
                    details={
                        "source_ip": artifact["source_ip"],
                        "destination_ip": artifact["destination_ip"],
                        "request_host": artifact.get("request_host", ""),
                        "request_path": artifact.get("request_path", ""),
                        "filename": artifact["filename"],
                        "type": artifact["type"],
                        "size": artifact["size"],
                        "sha256": artifact["sha256"],
                        "intel_matches": len(intel_matches),
                        "packet_index": artifact["packet_indexes"][0] if artifact.get("packet_indexes") else None,
                    },
                )
            )
        return detections

    def _detect_local_intel_matches(self) -> list[Detection]:
        detections: list[Detection] = []
        seen: set[tuple[str, str, str]] = set()
        for match in self.threat_intel_matches:
            key = (
                str(match.get("artifact_sha256", "")),
                str(match.get("match_type", "")),
                str(match.get("name", "")),
            )
            if key in seen:
                continue
            seen.add(key)
            severity = str(match.get("severity", "high"))
            detections.append(
                Detection(
                    severity=severity if severity in {"high", "medium", "low"} else "medium",
                    name="local_intel_match",
                    summary=(
                        f"Local threat intel matched {match.get('name', 'a known indicator')} for "
                        f"{match.get('filename', match.get('domain', 'the recovered activity'))}."
                    ),
                    details={
                        "source_ip": match.get("source_ip", ""),
                        "destination_ip": match.get("destination_ip", ""),
                        "filename": match.get("filename", ""),
                        "domain": match.get("domain", ""),
                        "match_type": match.get("match_type", ""),
                        "family": match.get("family", ""),
                        "sha256": match.get("artifact_sha256", ""),
                    },
                )
            )
        return detections

    def _detect_external_intel_hits(self) -> list[Detection]:
        detections: list[Detection] = []
        seen: set[tuple[str, str, str]] = set()
        for item in self.external_intel.get("items", []):
            severity = str(item.get("severity", "low"))
            disposition = str(item.get("disposition", ""))
            if severity not in {"high", "medium"} or disposition not in {"malicious", "suspicious"}:
                continue
            key = (
                str(item.get("provider", "")),
                str(item.get("indicator_type", "")),
                str(item.get("indicator", "")),
            )
            if key in seen:
                continue
            seen.add(key)
            context = item.get("context", {}) if isinstance(item.get("context"), dict) else {}
            detections.append(
                Detection(
                    severity=severity,
                    name="external_threat_intel_match",
                    summary=str(item.get("summary", "External threat-intel provider reported a hit.")),
                    details={
                        "provider": item.get("provider_label", item.get("provider", "")),
                        "indicator_type": item.get("indicator_type", ""),
                        "indicator": item.get("indicator", ""),
                        "source_ip": context.get("source_ip", "") or context.get("peer_ip", ""),
                        "destination_ip": context.get("destination_ip", "") or context.get("host_ip", ""),
                        "request_host": context.get("request_host", ""),
                    },
                )
            )
        return detections

    def _build_summary(self, detections: list[Detection]) -> dict[str, object]:
        severity_counts = {
            "high": sum(1 for item in detections if item.severity == "high"),
            "medium": sum(1 for item in detections if item.severity == "medium"),
            "low": sum(1 for item in detections if item.severity == "low"),
        }
        risk_score = min(
            100,
            (severity_counts["high"] * 30)
            + (severity_counts["medium"] * 16)
            + (severity_counts["low"] * 7)
            + (len(self.extracted_artifacts) * 4)
            + (len(self.threat_intel_matches) * 10)
            + (int(self.external_intel.get("summary", {}).get("high", 0)) * 8)
            + (int(self.external_intel.get("summary", {}).get("medium", 0)) * 4)
            + (5 if self.unsupported_packets else 0),
        )
        if severity_counts["high"]:
            headline = "Multiple high-severity behaviors were detected in this capture."
        elif severity_counts["medium"]:
            headline = "The capture shows moderate-risk patterns that deserve investigation."
        elif self.extracted_artifacts:
            headline = "Recovered artifacts and suspicious metadata were found in this capture."
        elif severity_counts["low"]:
            headline = "The capture contains low-severity findings and suspicious metadata."
        else:
            headline = "No explicit detections fired, but the summary still highlights activity patterns."
        return {
            "headline": headline,
            "risk_score": risk_score,
            "finding_count": len(detections),
            "severity_counts": severity_counts,
        }

    def _build_directory_services_summary(self) -> dict[str, object]:
        likely_servers = self._likely_directory_servers()
        kerberos_breakdown = Counter(str(event.get("message_name", "unknown")) for event in self.kerberos_events)
        ldap_breakdown = Counter(str(event.get("operation", "unknown")) for event in self.ldap_events)
        rpc_breakdown = Counter(str(event.get("packet_type", "unknown")) for event in self.rpc_events)
        return {
            "likely_directory_servers": likely_servers,
            "kerberos_activity": {
                "count": len(self.kerberos_events),
                "message_types": dict(kerberos_breakdown),
            },
            "ldap_activity": {
                "count": len(self.ldap_events),
                "operations": dict(ldap_breakdown),
            },
            "smb_activity": {
                "count": len(self.smb_events),
                "versions": dict(Counter(str(event.get("version", "unknown")) for event in self.smb_events)),
            },
            "rpc_activity": {
                "count": len(self.rpc_events),
                "packet_types": dict(rpc_breakdown),
                "drsuapi_packets": sum(1 for event in self.rpc_events if event.get("contains_drsuapi")),
            },
        }

    def _build_artifact_summary(self) -> dict[str, object]:
        suspicious_count = sum(1 for artifact in self.extracted_artifacts if artifact.get("suspicious"))
        return {
            "count": len(self.extracted_artifacts),
            "suspicious_count": suspicious_count,
            "intel_match_count": len(self.threat_intel_matches),
            "delivered_hosts": len({str(artifact["destination_ip"]) for artifact in self.extracted_artifacts}),
        }

    def _build_suspicious_hosts_summary(self) -> list[dict[str, object]]:
        hosts = [
            {
                "ip": host_ip,
                "score": data["score"],
                "role": classify_host(host_ip),
                "status": "high" if data["score"] >= 60 else "medium" if data["score"] >= 28 else "low",
                "evidence": data["evidence"][:6],
            }
            for host_ip, data in self.suspicious_hosts.items()
        ]
        return sorted(hosts, key=lambda item: item["score"], reverse=True)[:12]

    def _build_investigation_shortcuts(self, suspicious_hosts: list[dict[str, object]]) -> dict[str, object]:
        external_items = self.external_intel.get("items", []) if isinstance(self.external_intel, dict) else []

        file_pivots: list[dict[str, object]] = []
        for artifact in sorted(
            self.extracted_artifacts,
            key=lambda item: (len(item.get("intel_matches", [])), bool(item.get("suspicious")), int(item.get("size", 0))),
            reverse=True,
        )[:6]:
            external_hits = sum(1 for item in external_items if str(item.get("indicator", "")) == str(artifact.get("sha256", "")))
            severity = "high" if artifact.get("intel_matches") or external_hits else "medium" if artifact.get("suspicious") else "low"
            reasons = []
            if artifact.get("intel_matches"):
                reasons.append(f"{len(artifact['intel_matches'])} local intel matches")
            if external_hits:
                reasons.append(f"{external_hits} external reputation hits")
            if artifact.get("request_host"):
                reasons.append(f"delivered via {artifact['request_host']}")
            file_pivots.append(
                {
                    "kind": "file_hash",
                    "title": str(artifact.get("filename", "Recovered artifact")),
                    "indicator": str(artifact.get("sha256", "")),
                    "severity": severity,
                    "reason": ", ".join(reasons) or "Recovered from HTTP reassembly.",
                    "links": [
                        {"label": "VirusTotal", "url": f"https://www.virustotal.com/gui/file/{artifact['sha256']}"},
                        {"label": "AlienVault OTX", "url": f"https://otx.alienvault.com/indicator/file/{artifact['sha256']}"},
                    ],
                    "context": {
                        "source_ip": artifact.get("source_ip", ""),
                        "destination_ip": artifact.get("destination_ip", ""),
                        "request_host": artifact.get("request_host", ""),
                    },
                }
            )

        ip_pivots: list[dict[str, object]] = []
        for host in suspicious_hosts[:8]:
            ip = str(host.get("ip", ""))
            if not ip:
                continue
            ip_pivots.append(
                {
                    "kind": "ip",
                    "title": ip,
                    "indicator": ip,
                    "severity": str(host.get("status", "low")),
                    "reason": str((host.get("evidence") or ["Prioritized from host score."])[0]),
                    "links": [
                        {"label": "AbuseIPDB", "url": f"https://www.abuseipdb.com/check/{ip}"},
                        {"label": "Shodan", "url": f"https://www.shodan.io/host/{ip}"},
                        {"label": "Censys", "url": f"https://search.censys.io/hosts/{ip}"},
                    ],
                    "context": {"score": host.get("score", 0), "role": host.get("role", "")},
                }
            )

        domain_scores: dict[str, dict[str, object]] = {}
        for artifact in self.extracted_artifacts:
            domain = str(artifact.get("request_host", "")).strip().lower()
            if not domain:
                continue
            entry = domain_scores.setdefault(domain, {"score": 0, "reason": "Observed during artifact delivery."})
            entry["score"] += 4
        for event in self.http_events:
            if event.get("kind") != "request":
                continue
            domain = str(event.get("host", "")).strip().lower()
            if not domain:
                continue
            entry = domain_scores.setdefault(domain, {"score": 0, "reason": "Observed in HTTP requests."})
            entry["score"] += 3
        for query in self.dns_queries:
            if query.get("is_response"):
                continue
            domain = registered_domain(str(query.get("query", "")).strip().lower())
            if not domain:
                continue
            entry = domain_scores.setdefault(domain, {"score": 0, "reason": "Observed in DNS activity."})
            entry["score"] += 1

        domain_pivots: list[dict[str, object]] = []
        for domain, info in sorted(domain_scores.items(), key=lambda item: int(item[1]["score"]), reverse=True)[:8]:
            external_hits = sum(1 for item in external_items if str(item.get("indicator", "")).lower() == domain)
            severity = "high" if external_hits else "medium" if int(info["score"]) >= 4 else "low"
            domain_pivots.append(
                {
                    "kind": "domain",
                    "title": domain,
                    "indicator": domain,
                    "severity": severity,
                    "reason": str(info.get("reason", "Observed in capture.")),
                    "links": [
                        {"label": "VirusTotal Domain", "url": f"https://www.virustotal.com/gui/domain/{domain}"},
                    ],
                    "context": {"score": info.get("score", 0)},
                }
            )

        priority = (file_pivots[:4] + ip_pivots[:4] + domain_pivots[:4])[:10]
        return {
            "priority": priority,
            "file_hashes": file_pivots,
            "ips": ip_pivots,
            "domains": domain_pivots,
        }

    def _build_analyst_summary(
        self,
        summary: dict[str, object],
        directory_services: dict[str, object],
        detections: list[Detection],
    ) -> dict[str, object]:
        top_detection_summaries = [str(item.summary) for item in detections[:4]]
        overview_parts = [str(summary["headline"])]
        attack_hypotheses: list[str] = []
        recommended_actions: list[str] = []
        evidence: list[str] = []

        detection_names = {item.name for item in detections}
        if "ad_delegation_enumeration" in detection_names:
            attack_hypotheses.append(
                "LDAP traffic included delegation-related attributes, which is consistent with constrained delegation or RBCD reconnaissance."
            )
            recommended_actions.append(
                "Review recent LDAP query sources for delegated-object enumeration and validate who should be reading delegation attributes."
            )
        if "kerberoasting_suspected" in detection_names:
            attack_hypotheses.append(
                "The Kerberos pattern looks like bulk service-ticket collection, which can align with kerberoasting-style activity."
            )
            recommended_actions.append(
                "Check the requesting host for unusual service-ticket volume and review service accounts with SPNs and weak password posture."
            )
        if "dcsync_like_rpc" in detection_names:
            attack_hypotheses.append(
                "DRSUAPI replication traffic was observed, which is consistent with DCSync-like credential replication behavior."
            )
            recommended_actions.append(
                "Validate whether the source system should ever use replication APIs and inspect directory replication privileges immediately."
            )
        if "ldap_directory_reconnaissance" in detection_names and "ad_delegation_enumeration" not in detection_names:
            attack_hypotheses.append(
                "LDAP search volume suggests directory reconnaissance aimed at users, groups, or privileged object metadata."
            )
        if "bulk_asreq_activity" in detection_names:
            attack_hypotheses.append(
                "Repeated AS-REQ activity may reflect account discovery or pre-auth testing against the KDC."
            )
        if "periodic_beaconing" in detection_names:
            attack_hypotheses.append(
                "The capture also contains regular callback timing, so the host may be multitasking between control traffic and directory reconnaissance."
            )
        if self.extracted_artifacts:
            attack_hypotheses.append(
                "Reassembled HTTP traffic contained downloadable artifacts, which may represent staging or payload delivery."
            )
            recommended_actions.append(
                "Validate the recovered artifact hashes against your threat-intel sources and inspect the receiving host for execution or persistence."
            )
            for artifact in self.extracted_artifacts[:3]:
                evidence.append(
                    f"Recovered {artifact['filename']} ({artifact['type']}, sha256 {artifact['sha256'][:12]}...) delivered to {artifact['destination_ip']}."
                )
        if self.threat_intel_matches:
            attack_hypotheses.append(
                "One or more recovered indicators matched the local threat-intelligence database."
            )
            recommended_actions.append(
                "Treat the local intel matches as triage leads, then confirm them against your approved internal or vendor intelligence before escalating to malware attribution."
            )
            for match in self.threat_intel_matches[:3]:
                evidence.append(
                    f"Intel match on {match.get('filename', match.get('domain', 'indicator'))}: {match.get('name', 'known indicator')}."
                )
        external_summary = self.external_intel.get("summary", {}) if isinstance(self.external_intel, dict) else {}
        if int(external_summary.get("lookup_count", 0)):
            attack_hypotheses.append(
                "External reputation sources were queried for recovered indicators, giving extra confidence for any repeated malicious verdicts."
            )
            recommended_actions.append(
                "Treat external reputation hits as corroborating evidence, then validate them against your organization's own blocklists and case context."
            )
            evidence.append(
                f"External enrichment returned {external_summary.get('high', 0)} high, {external_summary.get('medium', 0)} medium, and {external_summary.get('low', 0)} low-severity reputation results."
            )
        if "suspicious_artifact_delivery" in detection_names:
            attack_hypotheses.append(
                "Recovered application content suggests file staging or payload delivery over cleartext HTTP."
            )
        if directory_services["likely_directory_servers"]:
            servers = ", ".join(entry["ip"] for entry in directory_services["likely_directory_servers"][:3])
            overview_parts.append(f"Likely directory-facing servers in this capture include {servers}.")
            first_server = directory_services["likely_directory_servers"][0]
            evidence.append(
                f"Directory-service candidate {first_server['ip']} exposed ports {','.join(str(port) for port in first_server['ports'])} to {first_server['client_count']} client hosts."
            )
        if directory_services["kerberos_activity"]["count"]:
            evidence.append(
                f"Observed {directory_services['kerberos_activity']['count']} Kerberos messages and {directory_services['ldap_activity']['count']} LDAP messages."
            )
        suspicious_hosts = self._build_suspicious_hosts_summary()
        if suspicious_hosts:
            top_host = suspicious_hosts[0]
            overview_parts.append(f"Highest-risk host candidate is {top_host['ip']} with score {top_host['score']}.")
            evidence.append(
                f"Top impacted host candidate {top_host['ip']} accumulated score {top_host['score']} from {len(top_host['evidence'])} evidence points."
            )
        if not attack_hypotheses:
            attack_hypotheses.append(
                "The traffic contains suspicious patterns, but the evidence is still best treated as triage signals rather than proof of a single intrusion path."
            )
        if not recommended_actions:
            recommended_actions.extend(
                [
                    "Correlate the suspicious source hosts with EDR, Windows event logs, and authentication logs.",
                    "Validate whether the observed protocols and ports are expected for the source systems in this segment.",
                ]
            )

        confidence = "high" if summary["severity_counts"]["high"] else "medium" if summary["finding_count"] else "low"
        return {
            "engine": "local heuristic analyst",
            "confidence": confidence,
            "overview": " ".join(overview_parts),
            "finding_summary": top_detection_summaries,
            "evidence": evidence[:6],
            "attack_hypotheses": attack_hypotheses[:4],
            "recommended_actions": recommended_actions[:5],
        }

    def _build_report(self, source_name: str, detections: list[Detection]) -> dict[str, object]:
        earliest = min(self.timestamps) if self.timestamps else None
        latest = max(self.timestamps) if self.timestamps else None
        host_inventory = []
        internal_hosts = 0
        external_hosts = 0

        for ip, stats in sorted(self.hosts.items(), key=lambda item: item[1].total_bytes, reverse=True):
            role = classify_host(ip)
            if role == "internal":
                internal_hosts += 1
            else:
                external_hosts += 1
            host_inventory.append(
                {
                    "ip": ip,
                    "role": role,
                    "packets_sent": stats.packets_sent,
                    "packets_received": stats.packets_received,
                    "bytes_sent": stats.bytes_sent,
                    "bytes_received": stats.bytes_received,
                    "total_packets": stats.total_packets,
                    "total_bytes": stats.total_bytes,
                    "peer_count": len(stats.peers),
                }
            )

        top_ports = [{"port": port, "packets": count} for port, count in self.port_counter.most_common(10)]
        top_flows = [
            {
                "flow": f"{key.src_ip}:{key.src_port} -> {key.dst_ip}:{key.dst_port}/{key.protocol}",
                "src_ip": key.src_ip,
                "dst_ip": key.dst_ip,
                "src_port": key.src_port,
                "dst_port": key.dst_port,
                "protocol": key.protocol,
                "packets": stats.packets,
                "bytes": stats.bytes,
                "payload_bytes": stats.payload_bytes,
                "duration_seconds": round(stats.duration, 6),
                "app_protocols": dict(stats.app_protocols),
            }
            for key, stats in sorted(self.flows.items(), key=lambda item: item[1].bytes, reverse=True)[:12]
        ]

        summary = self._build_summary(detections)
        directory_services = self._build_directory_services_summary()
        artifact_summary = self._build_artifact_summary()
        suspicious_hosts = self._build_suspicious_hosts_summary()
        investigation_shortcuts = self._build_investigation_shortcuts(suspicious_hosts)

        return {
            "report_version": 4,
            "metadata": {
                "source_name": source_name,
                "capture_format": self.capture_format,
                "capture_sha256": self.capture_sha256,
                "analyzed_at_utc": dt.datetime.now(tz=dt.timezone.utc).isoformat(),
                "capture_started_at_utc": iso_utc(earliest),
                "capture_ended_at_utc": iso_utc(latest),
                "duration_seconds": round((latest - earliest), 6) if earliest and latest else 0.0,
                "linktypes": [linktype_name(linktype) for linktype in sorted(self.linktypes_seen)],
            },
            "summary": summary,
            "analyst_summary": self._build_analyst_summary(summary, directory_services, detections),
            "stats": {
                "packets": self.packet_count,
                "bytes": self.total_bytes,
                "flows": len(self.flows),
                "unsupported_packets": self.unsupported_packets,
                "unique_hosts": len(self.hosts),
                "internal_hosts": internal_hosts,
                "external_hosts": external_hosts,
            },
            "layer4_protocols": dict(self.layer4_counter),
            "application_protocols": dict(self.app_counter),
            "directory_services": directory_services,
            "artifacts": self.extracted_artifacts[:20],
            "artifact_summary": artifact_summary,
            "threat_intel_matches": self.threat_intel_matches[:20],
            "external_intel": self.external_intel,
            "investigation_shortcuts": investigation_shortcuts,
            "suspicious_hosts": suspicious_hosts,
            "timeline": self.timeline_events[:MAX_TIMELINE_EVENTS],
            "important_frames": self.important_frames[:40],
            "top_talkers": host_inventory[:10],
            "host_inventory": host_inventory[:20],
            "top_destination_ports": top_ports,
            "top_flows": top_flows,
            "dns_queries": self.dns_queries[:25],
            "http_events": self.http_events[:25],
            "tls_client_hellos": self.tls_events[:25],
            "kerberos_events": self.kerberos_events[:25],
            "ldap_events": self.ldap_events[:25],
            "smb_events": self.smb_events[:25],
            "rpc_events": self.rpc_events[:25],
            "detections": [
                {
                    "severity": item.severity,
                    "name": item.name,
                    "summary": item.summary,
                    "details": item.details,
                }
                for item in detections
            ],
            "warnings": self.warnings,
        }


def analyze_capture_path(path: pathlib.Path, external_lookup_config: dict[str, object] | None = None) -> dict[str, object]:
    return PcapAnalyzer(external_lookup_config=external_lookup_config).analyze_path(path)


def analyze_capture_bytes(
    data: bytes,
    source_name: str = "<memory>",
    external_lookup_config: dict[str, object] | None = None,
) -> dict[str, object]:
    return PcapAnalyzer(external_lookup_config=external_lookup_config).analyze_bytes(data, source_name=source_name)


def print_terminal_report(report: dict[str, object]) -> None:
    metadata = report["metadata"]
    stats = report["stats"]
    summary = report["summary"]
    analyst_summary = report["analyst_summary"]
    directory_services = report["directory_services"]
    artifact_summary = report["artifact_summary"]
    external_intel = report.get("external_intel", {})

    print("PCAP Triage Report")
    print(f"Source: {metadata['source_name']}")
    print(
        f"Format: {metadata['capture_format']} | "
        f"Packets: {stats['packets']} | Flows: {stats['flows']} | "
        f"Bytes: {bytes_human(int(stats['bytes']))}"
    )
    print(
        f"Risk Score: {summary['risk_score']} | "
        f"Findings: {summary['finding_count']} | "
        f"Capture Span: {metadata['duration_seconds']:.2f}s"
    )
    print(f"Capture SHA256: {metadata['capture_sha256']}")
    print()

    print(summary["headline"])
    print()

    print("Analyst Summary")
    print(f"  {analyst_summary['overview']}")
    for line in analyst_summary["attack_hypotheses"][:3]:
        print(f"  - {line}")
    print()

    print("Top Talkers")
    for entry in report["top_talkers"][:8]:
        print(
            f"  {entry['ip']:39} "
            f"{entry['role']:8} packets={entry['total_packets']:3} bytes={bytes_human(int(entry['total_bytes']))}"
        )
    print()

    print("Detections")
    detections = report["detections"]
    if not detections:
        print("  none")
    else:
        for detection in detections:
            print(f"  [{detection['severity'].upper()}] {detection['summary']}")
    print()

    if directory_services["likely_directory_servers"]:
        print("Directory Services")
        for entry in directory_services["likely_directory_servers"][:4]:
            print(
                f"  {entry['ip']:39} ports={','.join(str(port) for port in entry['ports'])} "
                f"clients={entry['client_count']}"
            )
        print()

    if artifact_summary["count"]:
        print("Recovered Artifacts")
        for artifact in report["artifacts"][:5]:
            print(
                f"  {artifact['filename']:24} {artifact['type']:8} size={bytes_human(int(artifact['size']))} "
                f"dst={artifact['destination_ip']} sha256={artifact['sha256'][:16]}..."
            )
        if report["threat_intel_matches"]:
            print("Threat Intel Matches")
            for match in report["threat_intel_matches"][:5]:
                indicator = match.get("filename") or match.get("domain") or "indicator"
                print(f"  {indicator}: {match.get('name', 'known indicator')} [{match.get('match_type', 'match')}]")
        print()

    if external_intel.get("enabled"):
        print("External Intel")
        for provider in external_intel.get("providers", [])[:4]:
            print(f"  {provider.get('label', provider.get('provider', 'provider'))}: {provider.get('status', 'unknown')} - {provider.get('message', '')}")
        for item in external_intel.get("items", [])[:6]:
            print(
                f"  [{str(item.get('severity', 'low')).upper()}] "
                f"{item.get('provider_label', item.get('provider', 'provider'))} "
                f"{item.get('indicator_type', 'indicator')} {item.get('indicator', '')}: {item.get('summary', '')}"
            )
        print()

    if report["suspicious_hosts"]:
        print("Potentially Impacted Hosts")
        for host in report["suspicious_hosts"][:6]:
            print(f"  {host['ip']:39} score={host['score']:3} status={host['status']}")
        print()

    print("Application Protocols")
    if not report["application_protocols"]:
        print("  none identified")
    else:
        for name, count in report["application_protocols"].items():
            print(f"  {name:8} {count}")
    print()

    if report["http_events"]:
        print("HTTP Highlights")
        for event in report["http_events"][:5]:
            if event["kind"] == "request":
                print(f"  {event['src_ip']} -> {event['dst_ip']} {event['method']} {event['host']}{event['path']}")
            else:
                print(f"  {event['src_ip']} -> {event['dst_ip']} status={event['status_code']} {event['reason']}")
        print()

    if report["dns_queries"]:
        print("DNS Sample")
        for entry in report["dns_queries"][:5]:
            print(f"  {entry['src_ip']} -> {entry['dst_ip']} {entry['query']}")
        print()

    if report["warnings"]:
        print("Warnings")
        for warning in report["warnings"]:
            print(f"  - {warning}")


def write_json_report(report: dict[str, object], output_path: pathlib.Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
