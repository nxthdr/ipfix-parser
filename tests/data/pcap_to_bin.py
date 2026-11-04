#!/usr/bin/env python3
"""Extract the UDP payloads (IPFIX Messages) of a pcap file into a raw binary file.

Usage: python3 pcap_to_bin.py input.pcap output.bin

Supports classic pcap files (not pcapng) with Ethernet (DLT_EN10MB) or Linux
cooked (DLT_LINUX_SLL) link types, carrying IPv4 or IPv6 UDP packets. The
payloads are concatenated, so the output can be parsed with
`ipfix_parser::parse_messages`.
"""

import struct
import sys

LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113


def udp_payload(frame, linktype):
    if linktype == LINKTYPE_ETHERNET:
        offset, ethertype = 14, struct.unpack("!H", frame[12:14])[0]
    elif linktype == LINKTYPE_LINUX_SLL:
        offset, ethertype = 16, struct.unpack("!H", frame[14:16])[0]
    else:
        raise ValueError(f"unsupported link type {linktype}")

    if ethertype == 0x0800:  # IPv4
        ihl = (frame[offset] & 0x0F) * 4
        protocol = frame[offset + 9]
        offset += ihl
    elif ethertype == 0x86DD:  # IPv6 (no extension headers)
        protocol = frame[offset + 6]
        offset += 40
    else:
        return None

    if protocol != 17:  # UDP
        return None
    length = struct.unpack("!H", frame[offset + 4 : offset + 6])[0]
    return frame[offset + 8 : offset + length]


def main(src, dst):
    with open(src, "rb") as f:
        data = f.read()

    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        sys.exit("not a classic pcap file")
    linktype = struct.unpack(endian + "I", data[20:24])[0]

    offset, payloads = 24, []
    while offset + 16 <= len(data):
        incl_len = struct.unpack(endian + "I", data[offset + 8 : offset + 12])[0]
        frame = data[offset + 16 : offset + 16 + incl_len]
        offset += 16 + incl_len
        payload = udp_payload(frame, linktype)
        if payload:
            payloads.append(payload)

    with open(dst, "wb") as f:
        f.write(b"".join(payloads))
    print(f"{len(payloads)} messages, {sum(map(len, payloads))} bytes written to {dst}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
