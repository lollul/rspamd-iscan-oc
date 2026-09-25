package retry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

type Runner struct {
	Context             context.Context
	Fn                  func() error
	IsRetryable         func(error) bool
	MaxRetriesSameError int
	RetryIntervals      []time.Duration
	Logger              *slog.Logger
	ErrorKey            func(error) string

	lastErrorKey string
	failures     int
}

func (r *Runner) Run() error {
	ctx := r.Context
	if ctx == nil {
		ctx = context.Background()
	}

	for {
		if ctx.Err() != nil {
			return nil
		}

		err := r.Fn()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}

		if !r.IsRetryable(err) {
			return fmt.Errorf("non-retryable error: %w", err)
		}

		errorKey := r.errorKey(err)
		if errorKey == r.lastErrorKey {
			r.failures++
		} else {
			r.lastErrorKey = errorKey
			r.failures = 1
		}

		if r.failures >= r.MaxRetriesSameError {
			return fmt.Errorf("max. number of retries (%d) exceeded: %w", r.failures, err)
		}

		sleepTime := r.sleepTime()

		r.Logger.Warn(
			"retryable error occurred, retrying after pause",
			"error", err,
			"failures", r.failures,
			"max_retries", r.MaxRetriesSameError,
			"pause", sleepTime,
		)

		timer := time.NewTimer(sleepTime)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func (r *Runner) errorKey(err error) string {
	if r.ErrorKey != nil {
		return r.ErrorKey(err)
	}

	for {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			return fmt.Sprintf("%T:%v", err, err)
		}
		err = unwrapped
	}
}

func (r *Runner) sleepTime() time.Duration {
	if r.failures-1 < len(r.RetryIntervals) {
		return r.RetryIntervals[r.failures-1]
	}

	return r.RetryIntervals[len(r.RetryIntervals)-1]
}
