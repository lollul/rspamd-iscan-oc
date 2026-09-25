package iscan

import (
	"context"
	"errors"
	"iter"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fho/rspamd-iscan/internal/imapclt"
	"github.com/fho/rspamd-iscan/internal/testutils/mock"
)

type blockingIMAPClient struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingIMAPClient() *blockingIMAPClient {
	return &blockingIMAPClient{closed: make(chan struct{})}
}

func (c *blockingIMAPClient) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *blockingIMAPClient) Connect() error                         { return nil }
func (c *blockingIMAPClient) ConnectContext(context.Context) error   { return nil }
func (c *blockingIMAPClient) Done() <-chan struct{}                  { return c.closed }
func (c *blockingIMAPClient) MarkSeen([]uint32) error                { return nil }
func (c *blockingIMAPClient) Move([]uint32, string) error            { return nil }
func (c *blockingIMAPClient) Upload(string, string, time.Time) error { return nil }

func (c *blockingIMAPClient) Messages(string) iter.Seq2[*imapclt.Message, error] {
	return func(yield func(*imapclt.Message, error) bool) {
		<-c.closed
		yield(nil, errors.New("connection closed"))
	}
}

func (c *blockingIMAPClient) Monitor(string) (<-chan *imapclt.EventNewMessages, func() error, error) {
	ch := make(chan *imapclt.EventNewMessages)
	return ch, func() error { return nil }, nil
}

type idleTestIMAPClient struct {
	closed       chan struct{}
	once         sync.Once
	stops        atomic.Int32
	monitorCalls atomic.Int32
}

func newIdleTestIMAPClient() *idleTestIMAPClient {
	return &idleTestIMAPClient{closed: make(chan struct{})}
}

func (c *idleTestIMAPClient) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *idleTestIMAPClient) Connect() error                         { return nil }
func (c *idleTestIMAPClient) ConnectContext(context.Context) error   { return nil }
func (c *idleTestIMAPClient) Done() <-chan struct{}                  { return c.closed }
func (c *idleTestIMAPClient) MarkSeen([]uint32) error                { return nil }
func (c *idleTestIMAPClient) Move([]uint32, string) error            { return nil }
func (c *idleTestIMAPClient) Upload(string, string, time.Time) error { return nil }

func (c *idleTestIMAPClient) Messages(string) iter.Seq2[*imapclt.Message, error] {
	return func(func(*imapclt.Message, error) bool) {}
}

func (c *idleTestIMAPClient) Monitor(string) (<-chan *imapclt.EventNewMessages, func() error, error) {
	c.monitorCalls.Add(1)
	events := make(chan *imapclt.EventNewMessages)
	return events, func() error {
		c.stops.Add(1)
		return nil
	}, nil
}

func TestIMAPIdleLeaseRestartsMonitor(t *testing.T) {
	imapClient := newIdleTestIMAPClient()
	client, err := NewClient(&Config{
		ScanMailbox:      "scan",
		InboxMailbox:     "inbox",
		SpamMailboxName:  "spam",
		BackupMailbox:    "backup",
		SpamTreshold:     10,
		TempDir:          t.TempDir(),
		IMAPClient:       imapClient,
		Rspamc:           mock.NewRspamc(),
		OperationTimeout: 100 * time.Millisecond,
		IdleTimeout:      20 * time.Millisecond,
		ShutdownTimeout:  100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	runResult := make(chan error, 1)
	go func() { runResult <- client.Monitor() }()

	deadline := time.Now().Add(time.Second)
	for (imapClient.stops.Load() == 0 || imapClient.monitorCalls.Load() < 2) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if imapClient.stops.Load() == 0 {
		t.Fatal("expected idle monitor to be restarted")
	}
	if imapClient.monitorCalls.Load() < 2 {
		t.Fatal("expected a new IDLE monitor cycle")
	}

	if err := client.Stop(); err != nil {
		t.Fatalf("stopping client failed: %v", err)
	}
	if err := <-runResult; err != nil {
		t.Fatalf("monitor returned error during shutdown: %v", err)
	}
}

func TestRunIMAPPhaseClosesTransportOnTimeout(t *testing.T) {
	imapClient := newBlockingIMAPClient()
	client := &Client{
		clt:                imapClient,
		operationTimeout:   20 * time.Millisecond,
		shutdownTimeout:    100 * time.Millisecond,
		transportCloseDone: make(chan struct{}),
	}

	err := client.runIMAPPhase(context.Background(), func(context.Context) error {
		<-imapClient.closed
		return errors.New("connection closed")
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}

	select {
	case <-imapClient.closed:
	default:
		t.Fatal("expected IMAP transport to be closed")
	}
}
