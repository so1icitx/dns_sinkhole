

#  DNS-Sinkhole

A lightweight, educational DNS resolver and "sinkhole" written in Go. This project explores the mechanics of the DNS protocol by manually parsing UDP packets, validating domain names, and forging responses.

> **Note:** This is an educational project designed for learning Go's `net` and `encoding/binary` packages. It is not intended for production security environments, it's a deep dive into the "magic" behind DNS.

##  What’s under the hood?

This program doesn't use high-level DNS libraries. Instead, it interacts directly with the byte stream to understand how the internet's "phonebook" actually works.

### Key Features

* **Manual Packet Parsing:** Uses `binary.BigEndian` to decode and encode DNS headers and response structures directly from byte slices.
* **Domain Sinkholing:** Implements a closure-based blocklist checker that uses a `map[string]bool` for $O(1)$ lookups.
* **UDP Socket Handling:** Manually binds to a UDP port and manages the request/response lifecycle using `net.ListenUDP`.
* **Upstream Forwarding:** Forwards legitimate requests to Google's Public DNS (`8.8.8.8`) and relays the results back to the client.
* **Binary Forging:** Manually assembles DNS response packets, including setting flags for authoritative responses and handling `NXDOMAIN` errors.

##  How it works

1. **Listen:** The server sits on port `5353` waiting for UDP packets.
2. **Extract:** It strips the DNS header and parses the "Question" section to find the requested domain.
3. **Validate:** It uses a pre-compiled regex to ensure the domain isn't malicious/bogus data.
4. **Filter:** If the domain is in `blocklist.txt`, the request is ignored or sinkholed.
5. **Resolve/Forge:** If healthy, it fetches the real IP from an upstream provider, manually constructs a new DNS Answer, and sends it back.

##  Getting Started

### Prerequisites

* Go 1.25+
* A `blocklist.txt` file in the root directory (one domain per line).

### Running the Project

```bash

# Run the server
go run main.go

```

### Testing the Sinkhole

You can test it using `dig` or `nslookup` pointed at your local instance:

```bash
dig @127.0.0.1 -p 5353 google.com

```

---

