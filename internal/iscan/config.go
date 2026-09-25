package iscan

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"os"
	"time"

	"github.com/fho/rspamd-iscan/internal/imapclt"
)

const (
	// DefaultOperationTimeout bounds a mailbox processing phase.
	DefaultOperationTimeout = 5 * time.Minute
	// DefaultRspamdTimeout bounds one Rspamd request.
	DefaultRspamdTimeout = 2 * time.Minute
	// DefaultIdleTimeout bounds one quiet IMAP IDLE cycle.
	DefaultIdleTimeout = 10 * time.Minute
	// DefaultShutdownTimeout bounds graceful transport shutdown.
	DefaultShutdownTimeout = 10 * time.Second
)

type IMAPClient interface {
	Close() error
	Connect() error
	MarkSeen(uids []uint32) error
	Messages(mailbox string) iter.Seq2[*imapclt.Message, error]
	Monitor(mailbox string) (<-chan *imapclt.EventNewMessages, func() error, error)
	Move(uids []uint32, mailbox string) error
	Upload(path, mailbox string, ts time.Time) error
}

type Config struct {
	BackupMailbox         string
	HamMailbox            string
	InboxMailbox          string
	ScanMailbox           string
	SpamMailboxName       string
	UndetectedMailboxName string

	TempDir       string
	KeepTempFiles bool

	MarkLearnedAsSpamAsRead bool

	SpamTreshold float32

	Logger     *slog.Logger
	IMAPClient IMAPClient
	Rspamc     RspamdClient
	Context    context.Context

	OperationTimeout time.Duration
	RspamdTimeout    time.Duration
	IdleTimeout      time.Duration
	ShutdownTimeout  time.Duration
}

func (c *Config) validate() error {
	if c.SpamTreshold <= 0 {
		return errors.New("SpamTreshold must be >0")
	}

	if c.ScanMailbox == c.InboxMailbox {
		return errors.New("ScanMailbox and InboxMailbox must differ")
	}

	if c.ScanMailbox == c.UndetectedMailboxName {
		return errors.New("ScanMailbox and UndetectedMailbox must differ")
	}

	if c.ScanMailbox == c.HamMailbox {
		return errors.New("ScanMailbox and HamMailbox must differ")
	}

	if c.BackupMailbox == "" {
		return errors.New("BackupMailbox can not be empty")
	}

	if c.BackupMailbox == c.InboxMailbox {
		return errors.New("BackupMailbox and InboxMailbox must differ")
	}

	// Using the same mailbox for Spam, Ham and/or Backup would be weird but
	// should work fine!
	if c.SpamTreshold == 0 {
		return errors.New("SpamThreshold must be >0")
	}

	fd, err := os.Stat(c.TempDir)
	if err != nil {
		return fmt.Errorf("invalid TempDir (%s): %w", c.TempDir, err)
	}

	if !fd.IsDir() {
		return fmt.Errorf("specified TempDir (%s) is not a directory", c.TempDir)
	}

	if c.IMAPClient == nil {
		return errors.New("IMAP client can not be nil")
	}

	if c.Rspamc == nil {
		return errors.New("rspamc can not be nil")
	}

	return nil
}
