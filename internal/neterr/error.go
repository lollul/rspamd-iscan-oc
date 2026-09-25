package neterr

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
)

type retryableError interface {
	Retryable() bool
}

type retryKeyer interface {
	RetryKey() string
}

func IsRetryableError(err error) bool {
	var retryErr retryableError
	if errors.As(err, &retryErr) && retryErr.Retryable() {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, syscall.ECONNREFUSED),
		errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.ECONNABORTED),
		errors.Is(err, syscall.EPIPE),
		errors.Is(err, syscall.ETIMEDOUT),
		errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, io.ErrUnexpectedEOF),
		errors.Is(err, net.ErrClosed):
		return true
	default:
		return false
	}
}

func RetryKey(err error) string {
	var keyer retryKeyer
	if errors.As(err, &keyer) {
		return keyer.RetryKey()
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection-refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ECONNABORTED):
		return "connection-reset"
	case errors.Is(err, syscall.EPIPE):
		return "broken-pipe"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "network-unreachable"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected-eof"
	case errors.Is(err, net.ErrClosed):
		return "connection-closed"
	default:
		return "network"
	}
}
