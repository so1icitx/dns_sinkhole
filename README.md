<div align="center">
<h1>dns_sinkhole</h1>

A DNS resolver and sinkhole written in Go, without any DNS libraries. Parses
UDP packets manually, validates domains, and either forwards to upstream or
returns `0.0.0.0` for blocked domains.

[![Go Report Card](https://goreportcard.com/badge/github.com/so1icitx/dns_sinkhole)](https://goreportcard.com/report/github.com/so1icitx/dns_sinkhole)
[![License](https://img.shields.io/github/license/so1icitx/dns_sinkhole)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/so1icitx/dns_sinkhole)](go.mod)

</div>

## How it works

Queries arrive as raw UDP packets on port `5353`. The question section is
parsed manually from the byte stream ,  no DNS library touches the data. The
domain is validated with a compiled regex, then checked against a blocklist
loaded from `blocklist.txt` at startup.

**Blocked domains** get a synthesized A record pointing to `0.0.0.0`.

**Legitimate domains** are forwarded as-is to `8.8.8.8`. The upstream
response is parsed, the IP extracted, and a new answer record is assembled
by hand and sent back to the client.

**Non-existent domains** return NXDOMAIN ,  flags `0x8183`, answer count `0`.

DNS headers and response records are encoded and decoded directly with
`encoding/binary`. The response packet is built field by field into a byte
slice with no intermediate representation.

## Binary protocol

```
[ 2 bytes ]  ID       ,  copied from the client query
[ 2 bytes ]  Flags    ,  0x8180 (standard response) or 0x8183 (NXDOMAIN)
[ 2 bytes ]  QDCount  ,  question count (mirrored from query)
[ 2 bytes ]  ANCount  ,  1 for valid responses, 0 for NXDOMAIN
[ N bytes ]  Question ,  mirrored from the original query
[ 16 bytes]  Answer   ,  pointer, type, class, TTL, data length, IPv4 address
```

## Getting started

Add domains to `blocklist.txt`, one per line. A sample file is included.

```bash
go run main.go
```

Test with `dig`:

```bash
# Should return a real IP
dig @127.0.0.1 -p 5353 google.com

# Should return 0.0.0.0
dig @127.0.0.1 -p 5353 doubleclick.net
```

## Known limitations

- Only handles A record queries (IPv4)
- Single-threaded ,  one request at a time, no concurrency
- No caching; every query is forwarded to upstream
- Blocklist is loaded once at startup; requires a restart to reflect changes
