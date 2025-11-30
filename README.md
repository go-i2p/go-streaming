# go-streaming

I2P streaming library in Go using `go-i2cp` and `soypat/seqs`

## Overview

`go-streaming` implements the I2P streaming protocol, providing TCP-like reliable, ordered, bidirectional streams over the I2P anonymous network. This library is designed as a minimal, correct implementation suitable for building I2P applications in Go.

### What is I2P Streaming?

The I2P streaming protocol provides:

- **Reliable delivery**: Retransmission of lost packets
- **Ordered delivery**: Reassembly of out-of-order packets  
- **Flow control**: Window-based congestion control
- **Connection-oriented**: Three-way handshake (SYN/SYN-ACK/ACK)
- **net.Conn compatible**: Drop-in replacement for TCP connections

Unlike traditional TCP over IP, I2P streaming operates over the I2CP discrete message layer, treating each I2CP message as carrying a single TCP-like segment.

## Architecture

```text
Application (io.Reader/io.Writer)
     ↕
StreamConn (implements net.Conn)
     ↕
TCP Layer (github.com/soypat/seqs - packet construction)
     ↕
I2CP Layer (github.com/go-i2p/go-i2cp - discrete messages)
     ↕
I2P Network (anonymous routing via tunnels)
```

### Key Design Decisions

- **Packet-based transport**: Each I2CP message = one TCP segment (not fragmented)
- **MTU**: Default 1730 bytes payload (fits in 2x 1KB I2NP tunnel messages); 1812 bytes for ECIES
- **Windowing**: Packet count (not byte count) for flow control
- **Reliability**: Built on TCP semantics (sequence numbers, ACKs, retransmission)

## Protocol Features (per I2P Streaming Specification)

### Connection Lifecycle

- **Setup**: Three-way handshake (SYN → SYN-ACK → ACK)
- **Data Transfer**: Sequenced packets with selective acknowledgment
- **Close**: Bidirectional CLOSE handshake (like FIN but distinct)
- **Reset**: Abrupt termination with RST flag

### Flow Control

- **Window-based**: Max 128 packets in-flight (configurable)
- **Choking**: Receiver signals buffer full via optional delay field >60000ms
- **Unchoking**: Explicit signal to resume sending
- **Congestion Control**: Slow start + congestion avoidance (simplified for MVP)

### Reliability Features

- **Sequence Numbers**: 32-bit wrapping sequence tracking
- **ACKs**: Cumulative acknowledgment (ackThrough field)
- **Retransmission**: Exponential backoff on timeout
- **Out-of-Order**: Buffer and reorder packets

### Keepalive / Ping

- **ECHO packets**: Dedicated ping/pong with SIGNATURE_INCLUDED and FROM_INCLUDED flags
- **Optional delay**: Advisory field (0-60000ms) for ACK timing
- **Inactivity timeout**: Default 90 seconds

### Data Integrity

- No checksums in streaming protocol itself
- Relies on I2CP layer's gzip CRC-32 for error detection

## Current Status: Pre-MVP

This library is under active development. See [ROADMAP.md](ROADMAP.md) for detailed implementation plan.

### Planned MVP (v0.1.0-alpha)

- ✅ Three-way handshake (SYN/SYN-ACK/ACK)
- ✅ Basic data transfer with sequencing
- ✅ CLOSE handshake for clean shutdown
- ✅ `net.Conn` interface implementation
- ✅ Simple fixed-window flow control
- ⚠️  Simplified retransmission (fixed timeout)
- ⚠️  No congestion control (future)
- ⚠️  No ECHO/ping support initially (future)

See [ROADMAP.md](ROADMAP.md) for phased implementation details.

## Dependencies

**Required:**

- [`github.com/go-i2p/go-i2cp`](https://github.com/go-i2p/go-i2cp) - I2CP protocol transport (MIT)
- [`github.com/soypat/seqs`](https://github.com/soypat/seqs) - TCP packet construction/parsing (BSD-3-Clause)

**Standard Library Only**: No additional dependencies for MVP.

## Quick Start (Future)

```go
// Coming soon - example usage once implemented
import (
    "github.com/go-i2p/go-streaming"
)

// Client
conn, err := streaming.Dial("destination.b32.i2p:80")
if err != nil {
    panic(err)
}
defer conn.Close()
conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))

// Server
listener, err := streaming.Listen(":8080")
if err != nil {
    panic(err)
}
for {
    conn, err := listener.Accept()
    if err != nil {
        continue
    }
    go handleConn(conn) // Use like net.Conn
}
```

## Documentation

- [SPEC.md](SPEC.md) - Full I2P streaming protocol specification
- [ROADMAP.md](ROADMAP.md) - MVP implementation plan with phases
- [.github/copilot-instructions.md](.github/copilot-instructions.md) - Development guidelines

## Design Philosophy

1. **Correctness over performance**: Get basic protocol working first
2. **Simplicity over cleverness**: Obvious implementations preferred
3. **MVP-focused**: Defer optimizations until proven necessary
4. **I2P-native**: Designed for I2P's discrete message model, not adapted from IP networking

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

This project follows the I2P streaming protocol specification closely. Before contributing:

1. Read [SPEC.md](SPEC.md) to understand protocol requirements
2. Review [ROADMAP.md](ROADMAP.md) for current implementation priorities
3. Check [.github/copilot-instructions.md](.github/copilot-instructions.md) for coding standards

## References

- [I2P Streaming Library Specification](https://geti2p.net/spec/streaming)
- [I2CP Protocol](https://geti2p.net/spec/i2cp)
- [go-i2cp Implementation](https://github.com/go-i2p/go-i2cp)

