# go-streaming

I2P streaming protocol implementation in Go. Provides TCP-like reliable, ordered, bidirectional streams over the I2P anonymous network using `go-i2cp`.

## Overview

`go-streaming` is a minimal, correct MVP implementation of the I2P streaming protocol. It features:

- **Reliable delivery**: Sequence numbers, ACKs, and retransmission
- **Ordered delivery**: Reassembly of out-of-order packets  
- **Flow control**: Packet-based windowing per I2P spec
- **Connection-oriented**: Full three-way handshake + close protocol
- **net.Conn compatible**: Drop-in replacement for TCP connections
- **Callback-driven**: Integrates with I2CP SessionCallbacks for automatic packet routing

## Architecture

```
Application (io.Reader/io.Writer)
    ↕
StreamConn (implements net.Conn)
    ↕
StreamManager (routes packets from I2CP callbacks)
    ↕
I2P Streaming Protocol (TCP-like packet format)
    ↕
I2CP Layer (discrete message transport)
    ↕
I2P Network
```

**Key Design**: Each I2CP message carries one streaming packet. Default MTU is 1730 bytes (fits in 2x 1KB I2NP messages); ECIES uses 1812 bytes. Windowing uses packet counts, not bytes.

## Protocol Features

- **Setup**: Three-way handshake (SYN → SYN-ACK → ACK)
- **Data Transfer**: Sequenced packets with selective acknowledgment (NACK support)
- **Close**: Bidirectional CLOSE handshake
- **Flow Control**: Packet-based window (max 128 packets), choke mechanism for receiver-side signaling
- **Reliability**: Sequence tracking, cumulative ACKs, exponential backoff retransmission
- **Keepalive**: Inactivity timeout detection (90 seconds default)
- **Out-of-Order**: Buffering and reordering of packets
- **Data Integrity**: Relies on I2CP layer's gzip CRC-32

## Status: MVP Complete - Phase 6 Integration Testing ✅

The library is stable and production-ready for I2P applications. All core streaming features are implemented and tested.

### Implemented ✅

- ✅ Three-way handshake (SYN/SYN-ACK/ACK)
- ✅ Data transfer with sequence tracking and selective ACK
- ✅ CLOSE handshake for clean shutdown
- ✅ `net.Conn` interface (Read, Write, Close, SetDeadlines)
- ✅ Packet-based flow control (6-packet initial window, up to 128 packets)
- ✅ Exponential backoff retransmission
- ✅ Out-of-order packet buffering
- ✅ Ping/Pong (ECHO) for connection testing and RTT measurement
- ✅ **StreamManager** for automatic packet routing from I2CP callbacks
- ✅ **Connection multiplexing** on single I2CP session
- ✅ **172 unit tests** with 68.0% coverage, race-free
- ✅ **Integration tested** with real I2P connections
- ✅ Large data transfers (100KB+) validated
- ✅ Write deadline support (SetWriteDeadline)
- ✅ MTU negotiation (1730 bytes default, 1812 for ECIES)

### Known Limitations ⚠️

- **Limited RST**: Connection resets are basic
- **No half-close**: I2P streaming requires bidirectional CLOSE (see below)
- **No profile support**: Bulk vs. interactive profiles not implemented

These are intentional MVP trade-offs for clarity. Future versions will add optimizations based on real-world usage.

### Half-Close Behavior

Unlike TCP, I2P streaming does not support true half-close semantics where one side can close its write stream while continuing to read. Per the I2P streaming specification:

> "The connection is not closed until the peer responds with the CLOSE flag."

Both sides must send CLOSE to fully terminate a connection. When you call `Close()`, go-streaming:
1. Sends a CLOSE packet
2. Waits for the peer's CLOSE acknowledgment
3. Cleans up resources

Use `SetWriteDeadline` or `SetDeadline` if you need to timeout during close.

## Examples

Working examples in `examples/echo/`:

- **Server** - Listen for connections and echo data back
- **Client** - Connect to server and send test messages

Both demonstrate `net.Conn` compatibility with standard Go idioms.

## Dependencies

- [`github.com/go-i2p/go-i2cp`](https://github.com/go-i2p/go-i2cp) - I2CP protocol transport (MIT)
- Standard library only for packet construction

## Quick Start

### Basic Server

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
    
    // 2. Create StreamManager (handles automatic packet routing)
    manager, _ := streaming.NewStreamManager(client)
    manager.StartSession(context.Background())
    defer manager.Close()
    
    // 3. Listen for connections
    listener, _ := streaming.ListenWithManager(manager, 8080, 1730)
    defer listener.Close()
    
    // 4. Accept and echo connections
    for {
        conn, _ := listener.Accept()
        go io.Copy(conn, conn)
    }
}
```

### Basic Client

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
    
    // 3. Dial remote destination
    crypto := go_i2cp.NewCrypto()
    dest, _ := go_i2cp.NewDestinationFromBase64(destB64, crypto)
    
    conn, _ := streaming.DialWithManager(manager, dest, 0, 8080)
    defer conn.Close()
    
    // 4. Use like net.Conn
    conn.Write([]byte("Hello, I2P!"))
    buf := make([]byte, 1024)
    n, _ := conn.Read(buf)
}
```

See [examples/](examples/) directory for complete working examples.

## Logging

This library uses structured logging via [`github.com/go-i2p/logger`](https://github.com/go-i2p/logger). Logging is controlled through environment variables and is disabled by default for production use.

### Environment Variables

| Variable | Values | Description |
|----------|--------|-------------|
| `DEBUG_I2P` | `debug`, `warn`, `error` | Log level (default: disabled) |
| `WARNFAIL_I2P` | `true` | Fast-fail mode - exit on warnings |

### Usage Examples

```bash
# Normal operation (logging disabled)
go run ./examples/echo/server/

# Debug logging enabled
DEBUG_I2P=debug go run ./examples/echo/server/

# Warn-level with fast-fail
WARNFAIL_I2P=true DEBUG_I2P=warn go run ./examples/echo/server/

# Test with debug output
DEBUG_I2P=debug go test -v ./...
```

### Log Output Examples

**Connection establishment:**
```
DEBUG starting connection sendStreamID=0x12345678 remotePort=8080
DEBUG sending SYN packet seq=1 mtu=1730
DEBUG received SYN-ACK remoteStreamID=0xabcdef01 remoteMTU=1730
DEBUG connection established state=ESTABLISHED
```

**Packet processing (trace level):**
```
TRACE marshaling packet sendStreamID=0x12345678 seq=42 flags=0x0001 payloadLen=1500
TRACE packet marshaled totalBytes=1522
```

**Error handling:**
```
WARN signature verification failed error="invalid signature"
ERROR connection reset by peer streamID=0x12345678
```

**TCB cache operations:**
```
DEBUG TCB cache hit - applying cached connection parameters dest=a1b2c3d4 rtt=250ms window=12
DEBUG TCB cache update - stored connection parameters dest=a1b2c3d4 rtt=280ms updated=true
```

### Log Levels

| Level | Purpose |
|-------|---------|
| `trace` | Very detailed internal operations (packet marshal/unmarshal, signature operations) |
| `debug` | Connection state changes, cache operations, normal flow |
| `warn` | Recoverable issues (signature failures, rate limits exceeded) |
| `error` | Serious failures (connection resets, unrecoverable errors) |

## Testing

Run the full test suite:

```bash
go test -v ./...        # All tests
go test -race -v ./...  # With race detector
go test -cover ./...    # With coverage
```

**Status**: 172 tests, 68.0% coverage, race-free

System integration tests with real I2P router:

```bash
go test -tags=system -v -timeout=5m
```

Tests verify real I2CP connections, data transfer, and connection multiplexing. Tests that require a router will fail if no I2P router is available.

## Documentation

- [SPEC.md](SPEC.md) - Full I2P streaming protocol specification
- [examples/](examples/) - Working echo server/client examples

## License

MIT License - See [LICENSE](LICENSE) for details.

## References

- [I2P Streaming Protocol Spec](https://geti2p.net/spec/streaming)
- [I2CP Protocol](https://geti2p.net/spec/i2cp)
- [go-i2cp](https://github.com/go-i2p/go-i2cp)
