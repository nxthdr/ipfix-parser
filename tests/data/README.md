# Test Data

## ipfix.pcap / ipfix.bin

`ipfix.pcap` is a capture of the IPFIX export of [softflowd](https://github.com/irino/softflowd) v1.1.0, generated for this project (so it is covered by the project's MIT license). It holds 2 IPFIX Messages: 4 Templates (IPv4 and IPv6 flows), 1 Options Template (Metering Process statistics) and 31 Data Records.

`ipfix.bin` holds the same IPFIX Messages, without the pcap, Ethernet, IP and UDP headers. It is the input of the integration tests and the benchmarks.

### Regenerating the Capture

Live traffic is captured first, then replayed through softflowd offline, so the export does not depend on interface timing:

```bash
docker run --rm -v "$PWD/tests/data:/out" debian:bookworm-slim bash -c '
apt-get update -qq && apt-get install -y -qq softflowd tcpdump curl iputils-ping dnsutils
# 1. Capture some traffic
tcpdump -i eth0 -U -w /tmp/traffic.pcap not port 4739 &
sleep 1
for u in https://nxthdr.dev https://www.iana.org https://www.rfc-editor.org https://example.com http://neverssl.com; do curl -s -o /dev/null $u; done
ping -c 3 1.1.1.1; dig @1.1.1.1 nxthdr.dev; dig @8.8.8.8 example.org AAAA
sleep 1; kill %1; sleep 1
# 2. Export it as IPFIX (-v 10) and capture the export
tcpdump -i lo -U -w /out/ipfix.pcap udp port 4739 &
sleep 1
softflowd -d -r /tmp/traffic.pcap -v 10 -n 127.0.0.1:4739
sleep 2; kill %1
'
```

### Converting PCAP to Binary IPFIX Data

The capture holds several packets, so the UDP payloads are extracted with a small script (Python standard library only):

```bash
python3 tests/data/pcap_to_bin.py tests/data/ipfix.pcap tests/data/ipfix.bin
```

Verify the output starts with `00 0a` (IPFIX version 10):
```bash
hexdump -C tests/data/ipfix.bin | head -1
```

Then update the expectations of `tests/integration_test.rs` (Template IDs, number of Messages).

## Vendor Samples

Real exports from 13 vendors and exporters are used by `make test-vendors`. They are published by [logstash-codec-netflow](https://github.com/logstash-plugins/logstash-codec-netflow/tree/main/spec/codecs) under the Apache-2.0 license, so they are **not committed** here. They are downloaded at the commit pinned in `tests/integration_test.rs` into `tests/data/cache/` (git-ignored).
