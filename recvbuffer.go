package streaming

import "fmt"

// ErrBufferFull is returned by RecvBuffer.Write when there is not enough
// remaining capacity to accept the write without discarding unread data.
var ErrBufferFull = fmt.Errorf("receive buffer full")

// RecvBuffer is a fixed-capacity FIFO byte buffer used for the stream receive
// buffer.
//
// It replaces the previous github.com/armon/circbuf-based implementation,
// which is a tail-capture ring buffer: once full, additional writes silently
// overwrite the oldest unread bytes. That behavior is incompatible with the
// I2P streaming protocol's reliability guarantee ("reliable, in-order...
// streams") because it can drop already-acknowledged, unread data without
// any error signal.
//
// RecvBuffer instead rejects writes that would exceed capacity by returning
// ErrBufferFull, preserving all previously buffered (unread) data. Callers
// are expected to react to a full buffer using I2P streaming flow control
// (the choke/unchoke mechanism) until Reset() reclaims space by consuming
// buffered bytes.
type RecvBuffer struct {
	data []byte
	size int64
}

// NewBuffer creates a RecvBuffer with the given fixed capacity.
// The size must be greater than 0.
func NewBuffer(size int64) (*RecvBuffer, error) {
	if size <= 0 {
		return nil, fmt.Errorf("size must be positive")
	}
	return &RecvBuffer{
		data: make([]byte, 0, size),
		size: size,
	}, nil
}

// Write appends buf to the buffer. It returns ErrBufferFull without writing
// any bytes if buf does not fit within the remaining capacity, preserving
// all previously buffered (unread) data.
func (b *RecvBuffer) Write(buf []byte) (int, error) {
	if int64(len(buf)) > b.size-int64(len(b.data)) {
		return 0, ErrBufferFull
	}
	b.data = append(b.data, buf...)
	return len(buf), nil
}

// Bytes returns the currently buffered (unread) bytes. The returned slice
// should not be modified by the caller.
func (b *RecvBuffer) Bytes() []byte {
	return b.data
}

// Reset clears the buffer, discarding any buffered content.
func (b *RecvBuffer) Reset() {
	b.data = b.data[:0]
}

// Size returns the fixed capacity of the buffer.
func (b *RecvBuffer) Size() int64 {
	return b.size
}

// TotalWritten returns the number of bytes currently held in the buffer
// (i.e. written since the buffer was last Reset). This value is always
// bounded by Size(), since Write rejects writes that would exceed capacity.
func (b *RecvBuffer) TotalWritten() int64 {
	return int64(len(b.data))
}
