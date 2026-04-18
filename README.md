# go-streaming

I2P streaming protocol implementation in Go. Provides TCP-like reliable, ordered, bidirectional streams over the I2P anonymous network using `go-i2cp`.

## Features

### Implemented

- Three-way handshake (SYN/SYN-ACK/ACK)
- Data transfer with sequence tracking and selective ACK
- CLOSE handshake for clean shutdown
- `net.Conn` interface (Read, Write, Close, SetDeadlines)
- Packet-based flow control (6-packet initial window, up to 128 packets)
- Exponential backoff retransmission
- Out-of-order packet buffering
- Ping/Pong (ECHO) for RTT measurement
- StreamManager for automatic packet routing from I2CP callbacks
- Connection multiplexing on single I2CP session
- MTU negotiation (1730 bytes default, 1812 for ECIES)

### Planned

- Full RST (connection reset) support
- Bulk vs. interactive connection profiles

### Limitations

**No half-close**: I2P streaming requires bidirectional CLOSE. Both sides must send CLOSE to fully terminate a connection. When you call `Close()`:

1. Sends a CLOSE packet
2. Waits for the peer's CLOSE acknowledgment
3. Cleans up resources

Use `SetWriteDeadline` or `SetDeadline` if you need to timeout during close.

## Usage

### Server

```go
import (
    "context"
    "io"
    go_i2cp "github.com/go-i2p/go-i2cp"
    streaming "github.com/go-i2p/go-streaming"
)

func main() {
    client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})
    client.Connect(context.Background())
    defer client.Close()
    
    manager, _ := streaming.NewStreamManager(client)
    manager.StartSession(context.Background())
    defer manager.Close()
    
    listener, _ := streaming.ListenWithManager(manager, 8080, 1730)
    defer listener.Close()
    
    for {
        conn, _ := listener.Accept()
        go io.Copy(conn, conn)
    }
}
```

### Client

```go
import (
    "context"
    go_i2cp "github.com/go-i2p/go-i2cp"
    streaming "github.com/go-i2p/go-streaming"
)

func main() {
    client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})
    client.Connect(context.Background())
    defer client.Close()
    
    manager, _ := streaming.NewStreamManager(client)
    manager.StartSession(context.Background())
    defer manager.Close()
    
    crypto := go_i2cp.NewCrypto()
    dest, _ := go_i2cp.NewDestinationFromBase64(destB64, crypto)
    
    conn, _ := streaming.DialWithManager(manager, dest, 0, 8080)
    defer conn.Close()
    
    conn.Write([]byte("Hello, I2P!"))
    buf := make([]byte, 1024)
    n, _ := conn.Read(buf)
}
```

See [examples/](examples/) for complete working examples.

## Logging

Uses [`github.com/go-i2p/logger`](https://github.com/go-i2p/logger). Logging is disabled by default.

| Variable | Values | Description |
|----------|--------|-------------|
| `DEBUG_I2P` | `debug`, `warn`, `error` | Log level |
| `WARNFAIL_I2P` | `true` | Exit on warnings |

```bash
DEBUG_I2P=debug go run ./examples/echo/server/
```

## Testing

```bash
go test -v ./...        # All tests
go test -race -v ./...  # With race detector
go test -cover ./...    # With coverage
```

System tests (requires running I2P router):

```bash
go test -tags=system -v -timeout=5m
```

Containerized system tests (predictable router + test runner, no host ports):

```bash
./scripts/container/test-with-router.sh
```

This runs tests in a `router-tests` container against an `i2p-router` container with no published ports.

## Documentation

- [SPEC.md](SPEC.md) - I2P streaming protocol specification
- [I2P Streaming Protocol](https://geti2p.net/spec/streaming) - Official spec
- [go-i2cp](https://github.com/go-i2p/go-i2cp) - I2CP transport dependency

## License

MIT - See [LICENSE](LICENSE)
