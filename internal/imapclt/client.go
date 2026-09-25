package imapclt

import (
	"context"
	"crypto/tls"
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
)

type Client struct {
	address       string
	user          string
	password      string
	allowInsecure bool

	clt         *imapclient.Client
	rawConn     net.Conn
	connMu      sync.Mutex
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
}

type EventNewMessages struct {
	NewMsgCount uint32
}

// NewClient creates an new IMAP-Client.
// [*Client.Connect] must be called before any other methods.
func NewClient(cfg *Config) *Client {
	return &Client{
		address:       cfg.Address,
		user:          cfg.User,
		password:      cfg.Password,
		allowInsecure: cfg.AllowInsecure,
		logger:        log.EnsureLoggerInstance(cfg.Logger),
		logIMAPData:   cfg.LogIMAPData,
	}
}

// Connect establishes a connection to the IMAP server.
func (c *Client) Connect() error {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	return c.ConnectContext(ctx)
}

// ConnectContext establishes a connection to the IMAP server and interrupts
// an in-progress dial, TLS handshake, or login when ctx is canceled.
func (c *Client) ConnectContext(ctx context.Context) error {
	var debugWriter io.Writer
	if c.logIMAPData {
		debugWriter = NewDebugWriter(c.logger)
	}

	clt, err := c.dialContext(ctx, c.address, c.allowInsecure, &imapclient.Options{
		UnilateralDataHandler: &imapclient.UnilateralDataHandler{
			Mailbox: c.mailboxUpdateHandler,
		},
		Dialer:      &net.Dialer{Timeout: dialTimeout},
		DebugWriter: debugWriter,
	})
	if err != nil {
		return fmt.Errorf("establishing imap server connection failed: %w", err)
	}

	c.connMu.Lock()
	c.clt = clt
	c.connMu.Unlock()

	loginResult := make(chan error, 1)
	go func() {
		loginResult <- clt.Login(c.user, c.password).Wait()
	}()

	select {
	case err := <-loginResult:
		if err != nil {
			_ = c.Close()
			return fmt.Errorf("login at imap server failed: %w", err)
		}
	case <-ctx.Done():
		_ = c.Close()
		return fmt.Errorf("login at imap server canceled: %w", ctx.Err())
	}

	c.logger.Info("connection established, authentication succeeded",
		"event", "imap.connection_established")

	return nil
}

func (c *Client) Close() error {
	c.connMu.Lock()
	clt := c.clt
	rawConn := c.rawConn
	c.connMu.Unlock()

	if clt != nil {
		return clt.Close()
	}
	if rawConn != nil {
		return rawConn.Close()
	}

	return nil
}

// Done is closed when the underlying IMAP connection is closed.
func (c *Client) Done() <-chan struct{} {
	c.connMu.Lock()
	clt := c.clt
	c.connMu.Unlock()
	if clt == nil {
		return nil
	}

	return clt.Closed()
}

func (c *Client) dialContext(ctx context.Context, address string, allowInsecure bool, opts *imapclient.Options) (*imapclient.Client, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	logger := c.logger.With("server", address).With("timeout", dialTimeout)
	rawConn, err := c.dialRawContext(ctx, address)
	if err != nil {
		return nil, err
	}

	c.connMu.Lock()
	c.rawConn = rawConn
	c.connMu.Unlock()

	if port == "993" || port == "imaps" {
		logger.Debug("connecting to imap server", "tlsmode", "implicit")
		tlsConfig := cloneTLSConfig(opts.TLSConfig)
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = host
		}
		if tlsConfig.NextProtos == nil {
			tlsConfig.NextProtos = []string{"imap"}
		}

		tlsConn := tls.Client(rawConn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, err
		}

		return imapclient.New(tlsConn, opts), nil
	}

	logger.Debug("connecting to imap server", "tlsmode", "explicit")
	tlsConfig := cloneTLSConfig(opts.TLSConfig)
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = host
	}
	startTLSOptions := *opts
	startTLSOptions.TLSConfig = tlsConfig

	type startTLSResult struct {
		client *imapclient.Client
		err    error
	}
	startResult := make(chan startTLSResult, 1)
	go func() {
		client, err := imapclient.NewStartTLS(rawConn, &startTLSOptions)
		startResult <- startTLSResult{client: client, err: err}
	}()

	select {
	case result := <-startResult:
		if result.err != nil && allowInsecure && isStartTLSNotSupportedErr(result.err) {
			logger.Warn("establishing secure connection failed, connecting without encryption", "tlsmode", "none", "error", result.err)
			return c.dialInsecureContext(ctx, address, opts)
		}
		return result.client, result.err
	case <-ctx.Done():
		_ = rawConn.Close()
		return nil, ctx.Err()
	}
}

func (c *Client) dialRawContext(ctx context.Context, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: dialTimeout}
	return dialer.DialContext(ctx, "tcp", address)
}

func (c *Client) dialInsecureContext(ctx context.Context, address string, opts *imapclient.Options) (*imapclient.Client, error) {
	rawConn, err := c.dialRawContext(ctx, address)
	if err != nil {
		return nil, err
	}

	c.connMu.Lock()
	c.rawConn = rawConn
	c.connMu.Unlock()

	return imapclient.New(rawConn, opts), nil
}

func cloneTLSConfig(config *tls.Config) *tls.Config {
	if config == nil {
		return &tls.Config{}
	}

	return config.Clone()
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
// Message delivery to ch must not block. If delievery would block the
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

	idlecmd, err := c.clt.Idle()
	if err != nil {
		c.setNewMessagesCH(nil)
		close(ch)
		return nil, nil, err
	}

	return ch, func() error {
		logger.Debug("stopping idle command")
		err := errors.Join(idlecmd.Close(), idlecmd.Wait())
		c.setNewMessagesCH(nil)
		close(ch)
		return err
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
