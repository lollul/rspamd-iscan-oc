package imapclt

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/fho/rspamd-iscan/internal/log"
)

const (
	defChanBufSiz = 1
	dialTimeout   = 120 * time.Second
	// idleTimeout is the maximum time to wait in IDLE before sending a NOOP
	// to check connection health. RFC 2177 recommends at least 10 minutes.
	idleTimeout = 10 * time.Minute
)

type Client struct {
	address       string
	user          string
	password      string
	allowInsecure bool
	keepAlive     time.Duration

	clt         *imapclient.Client
	logger      *slog.Logger
	logIMAPData bool

	newMessagesCh chan<- *EventNewMessages
	mu            sync.Mutex
}

type Config struct {
	// Address is the address of the IMAP server. If the port is "993" or
	// "imaps" an implicit TLS (SSL) is established.
	// Otherwise a explicitl TLS (STARTTLS) connection is established.
	Address  string
	User     string
	Password string
	// AllowInsecure enables falling back to establishing the
	// connection without encryption when the server does not support TLS
	AllowInsecure bool
	Logger        *slog.Logger
	// LogIMAPData enables logging raw IMAP protocol data with debug
	// priority, it can contain sensitive information
	LogIMAPData bool
	// KeepAlive enables TCP keepalive on the IMAP connection.
	// If zero, keepalive is disabled. Default is 30 seconds.
	KeepAlive time.Duration
}

type EventNewMessages struct {
	NewMsgCount uint32
}

// NewClient creates an new IMAP-Client.
// [*Client.Connect] must be called before any other methods.
func NewClient(cfg *Config) *Client {
	keepAlive := cfg.KeepAlive
	if keepAlive == 0 {
		keepAlive = 30 * time.Second
	}
	return &Client{
		address:       cfg.Address,
		user:          cfg.User,
		password:      cfg.Password,
		allowInsecure: cfg.AllowInsecure,
		keepAlive:     keepAlive,
		logger:        log.EnsureLoggerInstance(cfg.Logger),
		logIMAPData:   cfg.LogIMAPData,
	}
}

// Connect establishes a connection the IMAP-Server.
func (c *Client) Connect() error {
	var debugWriter io.Writer
	if c.logIMAPData {
		debugWriter = NewDebugWriter(c.logger)
	}

	clt, err := c.dial(c.address, c.allowInsecure, &imapclient.Options{
		UnilateralDataHandler: &imapclient.UnilateralDataHandler{
			Mailbox: c.mailboxUpdateHandler,
		},
		Dialer:      &net.Dialer{Timeout: dialTimeout, KeepAlive: c.keepAlive},
		DebugWriter: debugWriter,
	})
	if err != nil {
		return fmt.Errorf("establishing imap server connection failed: %w", err)
	}
	c.clt = clt

	if err := clt.Login(c.user, c.password).Wait(); err != nil {
		return fmt.Errorf("login at imap server failed: %w", err)
	}

	c.logger.Info("connection established, authentication succeeded",
		"event", "imap.connection_established")

	return nil
}

func (c *Client) Close() error {
	return c.clt.Close()
}

func (c *Client) dial(address string, allowInsecure bool, opts *imapclient.Options) (*imapclient.Client, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	logger := c.logger.With("server", address).With("timeout", dialTimeout)

	if port == "993" || port == "imaps" {
		logger.Debug("connecting to imap server", "tlsmode", "implicit")
		return imapclient.DialTLS(address, opts)
	}

	logger.Debug("connecting to imap server", "tlsmode", "explicit")
	clt, err := imapclient.DialStartTLS(address, opts)
	if err != nil && allowInsecure && isStartTLSNotSupportedErr(err) {
		logger.Warn("establishing secure connection failed, connecting without encryption", "tlsmode", "none", "error", err)
		return imapclient.DialInsecure(address, opts)
	}

	return clt, err
}

func isStartTLSNotSupportedErr(err error) bool {
	var imapErr *imap.Error

	if errors.As(err, &imapErr) {
		return imapErr.Text == "STARTTLS not supported"
	}

	return false
}

func (c *Client) mailboxUpdateHandler(d *imapclient.UnilateralDataMailbox) {
	if d.NumMessages == nil {
		c.logger.Debug("ignoring mailbox update with nil NumMessages")
		return
	}

	c.logger.Debug("received mailbox update", "num_messages", *d.NumMessages)

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.newMessagesCh == nil {
		c.logger.Warn("ignoring mailbox update message, event channel is nil", "num_messages", *d.NumMessages)
		return
	}

	sendEventNewMessages(c.newMessagesCh, *d.NumMessages)
}

// Upload reads a message (mail) from file and appends it to an imap mailbox.
// The internal date of the message is set to ts.
func (c *Client) Upload(path, mailbox string, ts time.Time) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}

	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fd.Close()

	appendCmd := c.clt.Append(mailbox, fi.Size(), &imap.AppendOptions{Time: ts})

	_, err = io.Copy(appendCmd, fd)
	if err != nil {
		_ = appendCmd.Close()
		return fmt.Errorf("uploading mail to imap mailbox failed: %w", err)
	}

	err = appendCmd.Close()
	if err != nil {
		return fmt.Errorf("closing append command failed: %w", err)
	}

	_, err = appendCmd.Wait()
	if err != nil {
		return fmt.Errorf("waiting for append to finish failed: %w", err)
	}

	c.logger.Debug(
		"uploaded message to imap mailbox",
		lkMailbox, mailbox,
		"event", "imap.message_uploaded",
		"filepath", path,
	)

	return nil
}

// Monitor starts to monitor mailbox for new messages.
// When new messages are found an event is sent to ch.
// Message delivery to ch must not block. If delivery would block the
// message is discarded.
//
// While Monitor is running, running other IMAP operations will block forever!
// To issue other IMAP operations, the returned stop function must be called
// before!
func (c *Client) Monitor(mailbox string) (
	_ <-chan *EventNewMessages, stop func() error, _ error,
) {
	logger := c.logger.With(lkMailbox, mailbox)
	logger.Debug("starting to monitor mailbox for changes")

	ch := make(chan *EventNewMessages, defChanBufSiz)

	d, err := c.clt.Select(mailbox, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return nil, nil, fmt.Errorf("selecting mailbox %q failed: %w", mailbox, err)
	}

	if d.NumMessages != 0 {
		logger.Debug("mailbox has new message, skipping monitoring",
			"count", d.NumMessages,
		)
		sendEventNewMessages(ch, d.NumMessages)
		close(ch)
		return ch, func() error { return nil }, nil
	}

	c.setNewMessagesCH(ch)

	// Channel to signal the idle loop to stop
	stopCh := make(chan struct{})
	// Channel to return the final error from the idle loop
	errCh := make(chan error, 1)

	// Start the idle loop in a goroutine
	go func() {
		var idleCmd *imapclient.IdleCommand
		var lastErr error

		for {
			select {
			case <-stopCh:
				// Stop requested, close idle command if running
				if idleCmd != nil {
					_ = idleCmd.Close()
				}
				errCh <- lastErr
				return
			default:
			}

			// Start IDLE command
			idleCmd, err = c.clt.Idle()
			if err != nil {
				lastErr = fmt.Errorf("starting IDLE failed: %w", err)
				errCh <- lastErr
				return
			}

			logger.Debug("IDLE command started")

			// Wait for IDLE to complete in a goroutine
			idleDone := make(chan error, 1)
			go func() {
				idleDone <- idleCmd.Wait()
			}()

			select {
			case <-stopCh:
				// Stop requested during IDLE - close will make Wait() return
				_ = idleCmd.Close()
				// Wait for the goroutine to finish
				_ = <-idleDone
				errCh <- lastErr
				return
			case err := <-idleDone:
				// IDLE completed (server sent update or error)
				if err != nil {
					lastErr = fmt.Errorf("IDLE wait failed: %w", err)
					logger.Debug("IDLE command returned error", "error", err)
					errCh <- lastErr
					return
				}
				// IDLE completed successfully (server sent update)
				// The unilateral data handler will have sent the event
				// Continue loop to re-enter IDLE
				logger.Debug("IDLE command completed, re-entering")
				continue
			case <-time.After(idleTimeout):
				// Timeout reached, send NOOP to check connection health
				logger.Debug("IDLE timeout reached, sending NOOP to check connection")
				_ = idleCmd.Close()
				// Wait for the goroutine to finish (Wait() returns after Close())
				_ = <-idleDone

				// Send NOOP to verify connection is still alive
				noopCmd := c.clt.Noop()
				if err := noopCmd.Wait(); err != nil {
					lastErr = fmt.Errorf("NOOP wait failed: %w", err)
					errCh <- lastErr
					return
				}
				logger.Debug("NOOP successful, re-entering IDLE")
				// Continue loop to re-enter IDLE
				continue
			}
		}
	}()

	// Return the stop function that signals the idle loop to stop
	return ch, func() error {
		logger.Debug("stopping idle monitor")
		close(stopCh)
		// Wait for the idle loop to finish with a timeout
		select {
		case err := <-errCh:
			c.setNewMessagesCH(nil)
			close(ch)
			return err
		case <-time.After(10 * time.Second):
			logger.Warn("timeout stopping idle monitor, forcing close")
			c.setNewMessagesCH(nil)
			close(ch)
			return errors.New("timeout stopping idle monitor")
		}
	}, nil
}

func sendEventNewMessages(ch chan<- *EventNewMessages, newMessages uint32) {
	select {
	case ch <- &EventNewMessages{NewMsgCount: newMessages}:
	default:
	}
}

func asUIDSet(uids []uint32) imap.UIDSet {
	var result imap.UIDSet

	for _, uid := range uids {
		result.AddNum(imap.UID(uid))
	}
	return result
}

// Move moves the messages with the given uids to mailbox.
func (c *Client) Move(uids []uint32, mailbox string) error {
	if len(uids) == 0 {
		return errors.New("no uids were given")
	}

	_, err := c.clt.Move(asUIDSet(uids), mailbox).Wait()
	if err != nil {
		return err
	}

	c.logger.Debug(
		"moved imap messages",
		lkMailbox, mailbox,
		"count", len(uids),
		"event", "imap.messages_moved",
	)
	return err
}

// MarkSeen adds the \Seen flag to the messages with the given UIDs in the
// currently selected mailbox.
func (c *Client) MarkSeen(uids []uint32) error {
	if len(uids) == 0 {
		return errors.New("no uids were given")
	}

	storeCmd := c.clt.Store(asUIDSet(uids), &imap.StoreFlags{
		Op:     imap.StoreFlagsAdd,
		Silent: true,
		Flags:  []imap.Flag{imap.FlagSeen},
	}, nil)

	if err := storeCmd.Close(); err != nil {
		return fmt.Errorf("marking messages as seen failed: %w", err)
	}

	c.logger.Debug(
		"marked imap messages as seen",
		"count", len(uids),
		"event", "imap.messages_marked_seen",
	)

	return nil
}

func (c *Client) setNewMessagesCH(ch chan<- *EventNewMessages) {
	c.mu.Lock()
	c.newMessagesCh = ch
	c.mu.Unlock()
}
