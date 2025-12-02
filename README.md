# go-streaming

I2P streaming library in Go using `go-i2cp`

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
I2P Streaming Protocol (custom packet format)
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

## Current Status: Phase 6 Complete - Full Integration Testing ✅

This library is under active development. **Phase 6 (Integration Testing)** is complete with comprehensive test coverage!

### Recently Completed (Phase 6)

- ✅ **Integration Test Suite** - 151 tests with 67.8% coverage, race-free
- ✅ **SessionCallbacks Integration** - Full callback-driven packet reception
- ✅ **StreamManager** - Routes packets from I2CP callbacks to connections
- ✅ **Connection Multiplexing** - Multiple connections per I2CP session tested
- ✅ **Large Data Transfer** - Validated 100KB transfers with MTU chunking
- ✅ **Bidirectional Communication** - Simultaneous send/receive tested
- ✅ **CLOSE Handshake** - Proper connection teardown validated
- ✅ **Concurrent Operations** - Stress tested with 1000 concurrent ops

### Implemented (v0.1.0-alpha)

- ✅ Three-way handshake (SYN/SYN-ACK/ACK)
- ✅ Basic data transfer with sequencing
- ✅ CLOSE handshake for clean shutdown (bidirectional)
- ✅ `net.Conn` interface implementation
- ✅ Simple fixed-window flow control
- ✅ Echo server/client examples
- ✅ **Callback-based packet reception** via StreamManager
- ✅ **Connection multiplexing** - Multiple streams per session
- ✅ **Integration tested** - 151 tests, 67.8% coverage, race-free
- ✅ **Large transfers** - Validated 100KB+ with MTU chunking
- ⚠️  Simplified retransmission (fixed timeout)
- ⚠️  No congestion control (future)
- ⚠️  No ECHO/ping support initially (future)

See [ROADMAP.md](ROADMAP.md) for detailed implementation status.

### Examples

Working examples are available in the `examples/` directory:

- **[Echo Server/Client](examples/echo/)** - Demonstrates basic streaming API usage
  - Server: Listen for connections and echo data back
  - Client: Connect to server and send test messages
  - Shows `net.Conn` compatibility with standard Go idioms

**Note**: Examples require I2CP session setup (see [go-i2cp docs](https://github.com/go-i2p/go-i2cp)).

## Dependencies

**Required:**

- [`github.com/go-i2p/go-i2cp`](https://github.com/go-i2p/go-i2cp) - I2CP protocol transport (MIT)

**Standard Library Only**: All packet construction uses standard library encoding/binary.

## Quick Start

### Server Example

```go
import (
    "context"
    "io"
    go_i2cp "github.com/go-i2p/go-i2cp"
    streaming "github.com/go-i2p/go-streaming"
)

func main() {
    // 1. Connect to I2P router
    client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})
    client.Connect(context.Background())
    defer client.Close()
    
    // 2. Create StreamManager (handles SessionCallbacks)
    manager, _ := streaming.NewStreamManager(client)
    manager.StartSession(context.Background())
    defer manager.Close()
    
    // 3. Start ProcessIO loop (REQUIRED for callbacks!)
    go func() {
        for { client.ProcessIO(context.Background()) }
    }()
    
    // 4. Listen for connections
    listener, _ := streaming.ListenWithManager(manager, 8080, 1730)
    defer listener.Close()
    
    // 5. Accept and handle connections
    for {
        conn, _ := listener.Accept()
        go io.Copy(conn, conn) // Echo data back
    }
}
```

### Client Example

```go
import (
    "context"
    go_i2cp "github.com/go-i2p/go-i2cp"
    streaming "github.com/go-i2p/go-streaming"
)

func main() {
    // 1. Connect to I2P router
    client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})
    client.Connect(context.Background())
    defer client.Close()
    
    // 2. Create StreamManager
    manager, _ := streaming.NewStreamManager(client)
    manager.StartSession(context.Background())
    defer manager.Close()
    
    // 3. Start ProcessIO loop (REQUIRED!)
    go func() {
        for { client.ProcessIO(context.Background()) }
    }()
    
    // 4. Parse destination and dial
    crypto := go_i2cp.NewCrypto()
    dest, _ := go_i2cp.NewDestinationFromBase64(destB64, crypto)
    
    conn, _ := streaming.Dial(manager.Session(), dest, 0, 8080)
    defer conn.Close()
    
    // 5. Use like net.Conn
    conn.Write([]byte("Hello, I2P!"))
    buf := make([]byte, 1024)
    n, _ := conn.Read(buf)
}
```

**See [QUICKREF.md](QUICKREF.md) for a one-page reference guide!**

## Known Limitations

This is an **MVP (Minimum Viable Product)** implementation focused on correctness over performance. The following features are not yet implemented:

### Reliability & Error Handling

- **No robust retransmission**: Simplified retransmission with fixed timeout. Packet loss may cause stalls.
- **Out-of-order packets dropped**: No packet reordering buffer. Packets must arrive in sequence.
- **No NACK support**: Negative acknowledgments not implemented.
- **Limited RST handling**: Connection resets are basic.

### Performance & Optimization

- **Fixed window size**: Uses 6-packet window initially. No dynamic window sizing or congestion control.
- **No slow start/congestion avoidance**: Does not implement TCP-style congestion control algorithms.
- **No control block sharing**: Each connection independently estimates RTT/window size.
- **Simple buffering**: Uses basic buffers; not optimized for high throughput.

### Protocol Features

- **No ECHO/ping-pong**: Keepalive packets not implemented. Idle connections rely on I2CP timeouts.
- **No choking mechanism**: Flow control signals (optional delay >60000ms) not fully implemented.
- **No half-close**: FIN flag not supported; use CLOSE for connection termination.
- **No profile support**: Bulk vs. interactive profiles not implemented.
- **Single connection optimization**: StreamManager supports multiplexing but not optimized for many connections.

### Production Readiness

- **Limited testing**: 67.8% test coverage. Integration tests pass, but real-world edge cases not fully explored.
- **No metrics/monitoring**: No built-in observability (Prometheus, etc.).
- **No connection pooling**: Each connection requires separate handshake.
- **IPv6/ECIES optimization**: ECIES MTU (1812) supported but not extensively tested.

**These limitations are intentional for the MVP.** Future versions will address them based on real-world usage and feedback. See [ROADMAP.md](ROADMAP.md) for planned enhancements.

## Documentation

- **[QUICKREF.md](QUICKREF.md)** - One-page quick reference for SessionCallbacks integration ⭐
- **[INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md)** - Complete integration guide with patterns and examples ⭐
- [SESSIONCALLBACKS_INTEGRATION.md](SESSIONCALLBACKS_INTEGRATION.md) - Phase 3 implementation details
- [SPEC.md](SPEC.md) - Full I2P streaming protocol specification
- [ROADMAP.md](ROADMAP.md) - MVP implementation plan with phases
- [examples/](examples/) - Working echo server/client examples
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

