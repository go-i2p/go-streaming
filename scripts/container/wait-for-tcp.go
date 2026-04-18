package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	host := flag.String("host", "", "TCP host")
	port := flag.String("port", "", "TCP port")
	timeout := flag.Duration("timeout", 3*time.Minute, "maximum time to wait")
	interval := flag.Duration("interval", 1*time.Second, "retry interval")
	flag.Parse()

	if *host == "" || *port == "" {
		fmt.Fprintln(os.Stderr, "host and port are required")
		os.Exit(2)
	}

	address := net.JoinHostPort(*host, *port)
	deadline := time.Now().Add(*timeout)

	for {
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err == nil {
			_ = conn.Close()
			fmt.Printf("[router-tests] reached %s\n", address)
			return
		}

		if time.Now().After(deadline) {
			fmt.Fprintf(os.Stderr, "timed out waiting for %s: %v\n", address, err)
			os.Exit(1)
		}

		if !isTemporary(err) {
			time.Sleep(*interval)
			continue
		}
		time.Sleep(*interval)
	}
}

func isTemporary(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Temporary() || ne.Timeout()
	}
	return false
}
