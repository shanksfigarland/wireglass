from __future__ import annotations

import argparse
import pathlib
import random
import socket
import struct
import uuid

PCAPNG_BLOCK_SECTION_HEADER = 0x0A0D0D0A
PCAPNG_BLOCK_INTERFACE_DESCRIPTION = 0x00000001
PCAPNG_BLOCK_ENHANCED_PACKET = 0x00000006
DRSUAPI_UUID_BYTES = uuid.UUID("e3514235-4b06-11d1-ab04-00c04fc2dcd2").bytes_le


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) + data[offset + 1]
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def encode_dns_name(name: str) -> bytes:
    return b"".join(len(part).to_bytes(1, "big") + part.encode("ascii") for part in name.split(".")) + b"\x00"


def build_dns_query(transaction_id: int, qname: str) -> bytes:
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    question = encode_dns_name(qname) + struct.pack("!HH", 1, 1)
    return header + question


def build_ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    dst_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    src_mac = b"\x00\x11\x22\x33\x44\x55"
    return dst_mac + src_mac + struct.pack("!H", ethertype) + payload


def build_ipv4(src_ip: str, dst_ip: str, protocol: int, payload: bytes, identification: int) -> bytes:
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification & 0xFFFF,
        0,
        64,
        protocol,
        0,
        ip_bytes(src_ip),
        ip_bytes(dst_ip),
    )
    header_checksum = checksum(header)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification & 0xFFFF,
        0,
        64,
        protocol,
        header_checksum,
        ip_bytes(src_ip),
        ip_bytes(dst_ip),
    )
    return header + payload


def build_tcp(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    header = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, 0x50, flags, 65535, 0, 0)
    pseudo_header = ip_bytes(src_ip) + ip_bytes(dst_ip) + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    tcp_checksum = checksum(pseudo_header + header + payload)
    header = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, 0x50, flags, 65535, tcp_checksum, 0)
    return header + payload


def build_udp(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo_header = ip_bytes(src_ip) + ip_bytes(dst_ip) + struct.pack("!BBH", 0, 17, length)
    udp_checksum = checksum(pseudo_header + header + payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, udp_checksum)
    return header + payload


def ber_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def ldap_octet_string(value: str) -> bytes:
    encoded = value.encode("ascii")
    return b"\x04" + ber_length(len(encoded)) + encoded


def build_ldap_search_request(message_id: int, base_dn: str, query_terms: list[str]) -> bytes:
    body = ldap_octet_string(base_dn)
    body += b"\x0a\x01\x02"  # subtree
    body += b"\x0a\x01\x00"  # neverDerefAliases
    body += b"\x02\x01\x00"  # size limit
    body += b"\x02\x01\x00"  # time limit
    body += b"\x01\x01\x00"  # attrsOnly false
    filter_text = "(&(objectCategory=person)(" + ")(".join(query_terms) + "))"
    body += b"\x87" + ber_length(len(filter_text)) + filter_text.encode("ascii")
    attributes = b"".join(ldap_octet_string(term) for term in query_terms)
    body += b"\x30" + ber_length(len(attributes)) + attributes
    search_request = b"\x63" + ber_length(len(body)) + body
    message = b"\x02\x01" + bytes([message_id]) + search_request
    return b"\x30" + ber_length(len(message)) + message


def build_kerberos_message(tag: int, label: str) -> bytes:
    body = bytes([tag]) + label.encode("ascii")
    return len(body).to_bytes(4, "big") + body


def build_drsuapi_rpc_bind() -> bytes:
    rpc_header = b"\x05\x00\x0b\x03" + b"\x10\x00\x00\x00" + b"\x48\x00\x00\x00" + b"\x00\x00\x00\x00"
    body = rpc_header + b"DRSUAPI" + DRSUAPI_UUID_BYTES + b"\x00" * 24
    netbios = b"\x00" + len(body).to_bytes(3, "big")
    return netbios + body


def write_pcap(packets: list[tuple[float, bytes]], output_path: pathlib.Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, packet in sorted(packets, key=lambda item: item[0]):
            ts_sec = int(timestamp)
            ts_usec = int((timestamp - ts_sec) * 1_000_000)
            handle.write(struct.pack("<IIII", ts_sec, ts_usec, len(packet), len(packet)))
            handle.write(packet)


def build_pcapng_block(block_type: int, body: bytes) -> bytes:
    total_length = 12 + len(body)
    return struct.pack("<II", block_type, total_length) + body + struct.pack("<I", total_length)


def write_pcapng(packets: list[tuple[float, bytes]], output_path: pathlib.Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as handle:
        section_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        handle.write(build_pcapng_block(PCAPNG_BLOCK_SECTION_HEADER, section_body))

        idb_body = struct.pack("<HHI", 1, 0, 65535)
        idb_body += struct.pack("<HHB", 9, 1, 6) + b"\x00"
        idb_body += struct.pack("<HH", 0, 0)
        handle.write(build_pcapng_block(PCAPNG_BLOCK_INTERFACE_DESCRIPTION, idb_body))

        for timestamp, packet in sorted(packets, key=lambda item: item[0]):
            timestamp_microseconds = int(timestamp * 1_000_000)
            ts_high = (timestamp_microseconds >> 32) & 0xFFFFFFFF
            ts_low = timestamp_microseconds & 0xFFFFFFFF
            captured_len = len(packet)
            padding = (4 - (captured_len % 4)) % 4
            body = struct.pack("<IIIII", 0, ts_high, ts_low, captured_len, captured_len)
            body += packet + (b"\x00" * padding)
            body += struct.pack("<HH", 0, 0)
            handle.write(build_pcapng_block(PCAPNG_BLOCK_ENHANCED_PACKET, body))


def build_sample_packets() -> list[tuple[float, bytes]]:
    packets: list[tuple[float, bytes]] = []
    identification = 1
    base_ts = 1_712_400_000.0

    scan_ports = [22, 80, 135, 139, 443, 3389, 8080]
    for index, port in enumerate(scan_ports):
        tcp = build_tcp("10.0.0.5", "192.168.1.10", 40000 + index, port, seq=1000 + index, ack=0, flags=0x02)
        ipv4 = build_ipv4("10.0.0.5", "192.168.1.10", 6, tcp, identification)
        packets.append((base_ts + (index * 0.05), build_ethernet(ipv4)))
        identification += 1

    http_payload = (
        b"GET /login HTTP/1.1\r\n"
        b"Host: update-cache.example\r\n"
        b"User-Agent: pcap-triage-test/1.0\r\n"
        b"Accept: */*\r\n\r\n"
    )
    http_tcp = build_tcp("192.168.1.20", "93.184.216.34", 51514, 80, seq=1, ack=1, flags=0x18, payload=http_payload)
    http_ipv4 = build_ipv4("192.168.1.20", "93.184.216.34", 6, http_tcp, identification)
    packets.append((base_ts + 1.0, build_ethernet(http_ipv4)))
    identification += 1

    artifact_body = b"MZ" + (b"\x90" * 32) + (b"WireglassDemoPayload" * 10)
    http_response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=stage-loader.exe\r\n"
        + f"Content-Length: {len(artifact_body)}\r\n".encode("ascii")
        + b"Server: sample-cdn\r\n\r\n"
        + artifact_body
    )
    http_response_tcp = build_tcp(
        "93.184.216.34",
        "192.168.1.20",
        80,
        51514,
        seq=1,
        ack=len(http_payload) + 1,
        flags=0x18,
        payload=http_response,
    )
    http_response_ipv4 = build_ipv4("93.184.216.34", "192.168.1.20", 6, http_response_tcp, identification)
    packets.append((base_ts + 1.15, build_ethernet(http_response_ipv4)))
    identification += 1

    rng = random.Random(1337)
    for index in range(6):
        subdomain = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(26))
        query = f"{subdomain}.updates-example.com"
        dns_payload = build_dns_query(0x5000 + index, query)
        udp = build_udp("10.0.0.8", "8.8.8.8", 53000 + index, 53, dns_payload)
        ipv4 = build_ipv4("10.0.0.8", "8.8.8.8", 17, udp, identification)
        packets.append((base_ts + 2.0 + (index * 0.8), build_ethernet(ipv4)))
        identification += 1

    ldap_terms = [
        "servicePrincipalName",
        "msDS-AllowedToDelegateTo",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "userAccountControl",
    ]
    for index in range(3):
        ldap_payload = build_ldap_search_request(1 + index, "dc=corp,dc=local", ldap_terms)
        tcp = build_tcp(
            "10.0.0.25",
            "192.168.1.5",
            53010 + index,
            389,
            seq=100 + index,
            ack=1,
            flags=0x18,
            payload=ldap_payload,
        )
        ipv4 = build_ipv4("10.0.0.25", "192.168.1.5", 6, tcp, identification)
        packets.append((base_ts + 7.5 + (index * 0.35), build_ethernet(ipv4)))
        identification += 1

    for index in range(8):
        service = f"MSSQLSvc/sql{index}.corp.local:1433"
        kerberos_payload = build_kerberos_message(0x6C, service)
        tcp = build_tcp(
            "10.0.0.25",
            "192.168.1.5",
            54000 + index,
            88,
            seq=200 + index,
            ack=1,
            flags=0x18,
            payload=kerberos_payload,
        )
        ipv4 = build_ipv4("10.0.0.25", "192.168.1.5", 6, tcp, identification)
        packets.append((base_ts + 9.0 + (index * 0.2), build_ethernet(ipv4)))
        identification += 1

    for index in range(6):
        asreq_payload = build_kerberos_message(0x6A, f"user{index}@corp.local")
        udp = build_udp("10.0.0.40", "192.168.1.5", 55000 + index, 88, asreq_payload)
        ipv4 = build_ipv4("10.0.0.40", "192.168.1.5", 17, udp, identification)
        packets.append((base_ts + 11.5 + (index * 0.25), build_ethernet(ipv4)))
        identification += 1

    drsuapi_payload = build_drsuapi_rpc_bind()
    for port in (135, 445):
        tcp = build_tcp(
            "10.0.0.25",
            "192.168.1.5",
            56000 + port,
            port,
            seq=500 + port,
            ack=1,
            flags=0x18,
            payload=drsuapi_payload,
        )
        ipv4 = build_ipv4("10.0.0.25", "192.168.1.5", 6, tcp, identification)
        packets.append((base_ts + 14.0 + (0.08 if port == 445 else 0.0), build_ethernet(ipv4)))
        identification += 1

    for index in range(6):
        payload = f"beacon-{index:02d}-status".encode("ascii")
        tcp = build_tcp("192.168.1.50", "203.0.113.10", 51515, 443, seq=10 + index, ack=1, flags=0x18, payload=payload)
        ipv4 = build_ipv4("192.168.1.50", "203.0.113.10", 6, tcp, identification)
        packets.append((base_ts + 20.0 + (index * 10.0), build_ethernet(ipv4)))
        identification += 1

    return packets


def generate_capture(output_path: pathlib.Path) -> pathlib.Path:
    packets = build_sample_packets()
    if output_path.suffix.lower() == ".pcapng":
        write_pcapng(packets, output_path)
    else:
        write_pcap(packets, output_path)
    return output_path


def generate_capture_set(output_dir: pathlib.Path) -> dict[str, pathlib.Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = generate_capture(output_dir / "synthetic_suspicious.pcap")
    pcapng_path = generate_capture(output_dir / "synthetic_suspicious.pcapng")
    return {"pcap": pcap_path, "pcapng": pcapng_path}


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic suspicious capture files for local testing.")
    default_output = pathlib.Path(__file__).resolve().parent / "samples"
    parser.add_argument("--output", type=pathlib.Path, default=default_output)
    parser.add_argument("--format", choices=("pcap", "pcapng", "both"), default="both")
    args = parser.parse_args()
    if args.format == "both":
        outputs = generate_capture_set(args.output)
        for name, path in outputs.items():
            print(f"Wrote {name} sample to {path}")
    else:
        suffix = ".pcapng" if args.format == "pcapng" else ".pcap"
        output_path = generate_capture(args.output if args.output.suffix else args.output / f"synthetic_suspicious{suffix}")
        print(f"Wrote synthetic capture to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
