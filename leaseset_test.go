package streaming

import (
	"context"
	"testing"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
	"github.com/stretchr/testify/require"
)

// TestLeaseSetPublication tests if the router sends RequestVariableLeaseSet
func TestLeaseSetPublication(t *testing.T) {
	t.Log("=== LeaseSet Publication Test ===")
	t.Log("Testing if router requests LeaseSet for a session")
	t.Log("")

	// Create I2CP client
	t.Log("Step 1: Creating I2CP client...")
	client := go_i2cp.NewClient(nil)
	defer client.Close()
	t.Log("  ✓ Client created")

	// Connect to router
	t.Log("Step 2: Connecting to router...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	require.NoError(t, err, "should connect to router")
	t.Log("  ✓ Connected to router")

	// Create StreamManager
	t.Log("Step 3: Creating StreamManager...")
	manager, err := NewStreamManager(client)
	require.NoError(t, err, "should create manager")
	defer manager.Close()
	t.Log("  ✓ Manager created")

	// Configure session
	t.Log("Step 4: Configuring session...")
	manager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	manager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "leaseset-test")
	manager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_INBOUND_QUANTITY, "2")
	manager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "2")
	t.Log("  ✓ Session configured")

	// Start ProcessIO
	t.Log("Step 5: Starting ProcessIO...")
	go func() {
		for {
			if err := client.ProcessIO(context.Background()); err != nil {
				if err == go_i2cp.ErrClientClosed {
					return
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	time.Sleep(100 * time.Millisecond)
	t.Log("  ✓ ProcessIO started")

	// Start session
	t.Log("Step 6: Starting I2CP session...")
	sessionCtx, sessionCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer sessionCancel()

	err = manager.StartSession(sessionCtx)
	require.NoError(t, err, "should start session")
	t.Log("  ✓ Session started")
	t.Logf("  ✓ Session ID: %d", manager.session.ID())
	t.Logf("  ✓ Destination: %s...", manager.Destination().Base32()[:52])

	// Wait for LeaseSet
	t.Log("")
	t.Log("Step 7: Waiting for LeaseSet (up to 2 minutes)...")
	t.Log("  (Router should build tunnels and send RequestVariableLeaseSet)")

	timeout := time.After(120 * time.Second)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-manager.leaseSetReady:
			t.Log("  ✓ LeaseSet published!")
			t.Log("  ✓ Router sent RequestVariableLeaseSet and we responded")
			return

		case <-ticker.C:
			elapsed := 120 - int(time.Until(time.Now().Add(120*time.Second)).Seconds())
			t.Logf("  ⏱ Still waiting... (%d seconds elapsed)", elapsed)

		case <-timeout:
			t.Log("  ✗ TIMEOUT: Router never sent RequestVariableLeaseSet")
			t.Log("")
			t.Log("Possible reasons:")
			t.Log("  1. Router hasn't built tunnels yet (shouldn't take > 2 min)")
			t.Log("  2. Router doesn't request LeaseSet for transient sessions")
			t.Log("  3. Message was sent but ProcessIO didn't receive it")
			t.Log("  4. go-i2cp didn't handle RequestVariableLeaseSet message")
			t.Fatal("Router did not request LeaseSet within 2 minutes")
		}
	}
}
