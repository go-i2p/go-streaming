package streaming

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewBufferRejectsNonPositiveSize verifies size validation.
func TestNewBufferRejectsNonPositiveSize(t *testing.T) {
	_, err := NewBuffer(0)
	require.Error(t, err)

	_, err = NewBuffer(-1)
	require.Error(t, err)
}

// TestRecvBufferBasicWriteReadCycle verifies the basic Write/Bytes/Reset cycle.
func TestRecvBufferBasicWriteReadCycle(t *testing.T) {
	buf, err := NewBuffer(1024)
	require.NoError(t, err)

	n, err := buf.Write([]byte("hello"))
	require.NoError(t, err)
	require.Equal(t, 5, n)
	require.Equal(t, []byte("hello"), buf.Bytes())
	require.Equal(t, int64(5), buf.TotalWritten())
	require.Equal(t, int64(1024), buf.Size())

	buf.Reset()
	require.Equal(t, int64(0), buf.TotalWritten())
	require.Empty(t, buf.Bytes())
}

// TestRecvBufferRejectsOverflowPreservingData verifies that writes exceeding the
// remaining capacity are rejected with ErrBufferFull, and that no previously
// buffered data is discarded or overwritten. This directly validates the fix
// for the AUDIT.md "Receive buffer uses ring buffer instead of FIFO queue"
// finding: the old github.com/armon/circbuf-backed implementation silently
// overwrote the oldest unread bytes once full, which is a data corruption
// risk for a protocol that promises reliable, in-order delivery.
func TestRecvBufferRejectsOverflowPreservingData(t *testing.T) {
	const capacity = 64 * 1024 // matches the receive buffer size used by StreamConn
	buf, err := NewBuffer(capacity)
	require.NoError(t, err)

	// Fill the buffer completely with a known pattern.
	first := bytes.Repeat([]byte{0xAB}, capacity)
	n, err := buf.Write(first)
	require.NoError(t, err)
	require.Equal(t, capacity, n)
	require.Equal(t, int64(capacity), buf.TotalWritten())

	// Any further write, even a single byte, must be rejected outright.
	n, err = buf.Write([]byte{0xFF})
	require.ErrorIs(t, err, ErrBufferFull)
	require.Equal(t, 0, n)

	// All of the original data must still be intact and unread - no silent
	// overwrite of the oldest bytes, unlike the ring buffer this replaces.
	require.Equal(t, first, buf.Bytes())
	require.Equal(t, int64(capacity), buf.TotalWritten())
}

// TestRecvBufferMultiplePacketsWithoutReadStayWithinCapacity verifies that
// several writes (simulating several arriving packets) accumulate correctly
// and that TotalWritten() reflects the true fill level relative to capacity,
// bounded by Size() - closing the related AUDIT.md finding that TotalWritten()
// could exceed Size() and produce a bufferUsage ratio greater than 1.0.
func TestRecvBufferMultiplePacketsWithoutReadStayWithinCapacity(t *testing.T) {
	buf, err := NewBuffer(100)
	require.NoError(t, err)

	for _, chunk := range [][]byte{
		bytes.Repeat([]byte{1}, 40),
		bytes.Repeat([]byte{2}, 40),
	} {
		n, err := buf.Write(chunk)
		require.NoError(t, err)
		require.Equal(t, len(chunk), n)
	}

	require.Equal(t, int64(80), buf.TotalWritten())
	require.LessOrEqual(t, buf.TotalWritten(), buf.Size())

	// A third write that would exceed the remaining 20 bytes of capacity
	// must fail rather than silently discarding the first two chunks.
	_, err = buf.Write(bytes.Repeat([]byte{3}, 21))
	require.ErrorIs(t, err, ErrBufferFull)
	require.Equal(t, int64(80), buf.TotalWritten(), "existing data must be unaffected by a rejected write")

	// A write that exactly fits the remaining capacity succeeds.
	n, err := buf.Write(bytes.Repeat([]byte{3}, 20))
	require.NoError(t, err)
	require.Equal(t, 20, n)
	require.Equal(t, int64(100), buf.TotalWritten())
}
