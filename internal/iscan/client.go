package iscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fho/rspamd-iscan/internal/imapclt"
	"github.com/fho/rspamd-iscan/internal/log"
	"github.com/fho/rspamd-iscan/internal/mail"
	"github.com/fho/rspamd-iscan/internal/neterr"
	"github.com/fho/rspamd-iscan/internal/rspamc"
)

const (
	hdrPrefix      = "X-rspamd-iscan-"
	hdrRspamdScore = hdrPrefix + "Score"
)

type RspamdClient interface {
	Check(context.Context, io.Reader) (*rspamc.CheckResult, error)
	Spam(context.Context, io.Reader) error
	Ham(context.Context, io.Reader) error
}

type Client struct {
	clt    IMAPClient
	rspamc RspamdClient
	logger *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	stopOnce           sync.Once
	runMu              sync.Mutex
	wgRun              sync.WaitGroup
	transportCloseOnce sync.Once
	transportCloseDone chan struct{}
	transportCloseErr  error

	scanMailbox       string
	inboxMailbox      string
	spamMailbox       string
	hamMailbox        string
	backupMailbox     string
	undetectedMailbox string
	spamTreshold      float32

	tempDir       string
	keepTempFiles bool

	markLearnedAsSpamAsRead bool

	learnInterval time.Duration

	operationTimeout time.Duration
	rspamdTimeout    time.Duration
	idleTimeout      time.Duration
	shutdownTimeout  time.Duration

	// cntProcessedMails counts the number of emails that have been processed
	// in the [Client.scanMailbox], [Client.hamMailbox] and [Client.
	// spamMailbox].
	// It is only used in tests.
	cntProcessedMails atomic.Uint64
}

type scannedMail struct {
	Path        string
	UID         uint32
	Envelope    *imapclt.Envelope
	CheckResult *rspamc.CheckResult
}

type learnFn func(context.Context, io.Reader) error

func NewClient(cfg *Config) (*Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	parent := cfg.Context
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)

	operationTimeout := cfg.OperationTimeout
	if operationTimeout <= 0 {
		operationTimeout = DefaultOperationTimeout
	}
	rspamdTimeout := cfg.RspamdTimeout
	if rspamdTimeout <= 0 {
		rspamdTimeout = DefaultRspamdTimeout
	}
	idleTimeout := cfg.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = DefaultIdleTimeout
	}
	shutdownTimeout := cfg.ShutdownTimeout
	if shutdownTimeout <= 0 {
		shutdownTimeout = DefaultShutdownTimeout
	}

	c := &Client{
		clt:                     cfg.IMAPClient,
		logger:                  log.EnsureLoggerInstance(cfg.Logger),
		inboxMailbox:            cfg.InboxMailbox,
		scanMailbox:             cfg.ScanMailbox,
		spamMailbox:             cfg.SpamMailboxName,
		hamMailbox:              cfg.HamMailbox,
		undetectedMailbox:       cfg.UndetectedMailboxName,
		rspamc:                  cfg.Rspamc,
		spamTreshold:            cfg.SpamTreshold,
		learnInterval:           30 * time.Minute,
		backupMailbox:           cfg.BackupMailbox,
		tempDir:                 cfg.TempDir,
		keepTempFiles:           cfg.KeepTempFiles,
		markLearnedAsSpamAsRead: cfg.MarkLearnedAsSpamAsRead,
		operationTimeout:        operationTimeout,
		rspamdTimeout:           rspamdTimeout,
		idleTimeout:             idleTimeout,
		shutdownTimeout:         shutdownTimeout,
		transportCloseDone:      make(chan struct{}),
		ctx:                     ctx,
		cancel:                  cancel,
	}

	return c, nil
}

func (c *Client) ProcessHam() error {
	return c.runIMAPPhase(c.ctx, c.processHam)
}

func (c *Client) processHam(ctx context.Context) error {
	if c.hamMailbox == "" {
		return nil
	}

	return c.learn(ctx, c.hamMailbox, c.inboxMailbox, false, c.rspamc.Ham)
}

func (c *Client) ProcessSpam() error {
	return c.runIMAPPhase(c.ctx, c.processSpam)
}

func (c *Client) processSpam(ctx context.Context) error {
	if c.undetectedMailbox == "" {
		return nil
	}

	return c.learn(ctx, c.undetectedMailbox, c.spamMailbox, c.markLearnedAsSpamAsRead, c.rspamc.Spam)
}

func (c *Client) learn(ctx context.Context, srcMailbox, destMailbox string, markAsSeen bool, learnFn learnFn) error {
	var processedMsgUIDs []uint32

	logger := c.logger.With("mailbox.source", srcMailbox)

	logger.Info("checking mailbox for new messages to learn")

	for msg, err := range c.clt.Messages(srcMailbox) {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}

		if err != nil {
			if errMalformed, ok := errors.AsType[*imapclt.ErrMalformedMsg](err); ok {
				logger.Warn(
					"skipping malformed message",
					"mail.uid", errMalformed.UID,
					"error", err,
					"event", "imap.msg_malformed",
				)
				processedMsgUIDs = append(processedMsgUIDs, errMalformed.UID)
				continue
			}

			return fmt.Errorf("fetching messages from imap mailbox failed: %w", err)
		}

		logger := c.logger.With("mail.subject", msg.Envelope.Subject, "mail.uid", msg.UID)
		logger.Debug("fetched message")

		// TODO: retry Check if it failed with a temporary error
		learnCtx, cancel := context.WithTimeout(ctx, c.rspamdTimeout)
		err = learnFn(learnCtx, msg.Message)
		cancel()
		if err != nil {
			logger.Warn("learning message failed", "error", err,
				"event", "rspamd.msg_learn_failed")
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) ||
				neterr.IsRetryableError(err) {
				return err
			}
			return nil
		}

		logger.Info("learned message", "event", "rspamd.msg_learned")
		processedMsgUIDs = append(processedMsgUIDs, msg.UID)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if len(processedMsgUIDs) == 0 {
		return nil
	}

	if markAsSeen {
		if err := c.clt.MarkSeen(processedMsgUIDs); err != nil {
			logger.Warn("marking learned message as seen failed",
				"error", err)
		}
	}

	err := c.clt.Move(processedMsgUIDs, destMailbox)
	if err != nil {
		return fmt.Errorf("moving messages after learning failed: %w", err)
	}

	c.cntProcessedMails.Add(uint64(len(processedMsgUIDs)))

	return nil
}

func asHdrMap(prefix string, scores map[string]*rspamc.Symbol, skipZeroScores bool) []*mail.Header {
	result := make([]*mail.Header, 0, len(scores))

	for _, v := range scores {
		if skipZeroScores && v.Score == 0 {
			continue
		}

		result = append(result, &mail.Header{
			Name: prefix + v.Name,
			Body: fmt.Sprint(v.Score),
		})
	}

	return result
}

func addScanResultHeaders(mailFilepath string, result *rspamc.CheckResult) error {
	var hdrsData []byte

	hdrs := asHdrMap(hdrPrefix+"Symbol-", result.Symbols, true)
	hdrs = append(hdrs, &mail.Header{
		Name: hdrRspamdScore,
		Body: fmt.Sprint(result.Score),
	})

	sortHeaders(hdrs)

	// TODO: instead of adding a header line per symbol, add a multiline
	// header with all symbols
	hdrsData, err := mail.AsHeaders(hdrs)
	if err != nil {
		return err
	}

	return mail.AddHeaders(mailFilepath, hdrsData)
}

func sortHeaders(hdrs []*mail.Header) {
	slices.SortFunc(hdrs, func(a, b *mail.Header) int {
		if a.Name == hdrRspamdScore {
			return 1
		}

		if b.Name == hdrRspamdScore {
			return -1
		}

		score := strings.Compare(a.Name, b.Name)
		if score == 0 {
			return strings.Compare(a.Body, b.Body)
		}

		return score
	})
}

func (c *Client) isSpam(r *rspamc.CheckResult) bool {
	return r.Score >= c.spamTreshold
}

func (c *Client) removeTempMail(mail *scannedMail) {
	if c.keepTempFiles || mail == nil {
		return
	}

	if err := os.Remove(mail.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		c.logger.Warn("deleting temporary email failed",
			"error", err,
			"filepath", mail.Path,
			"event", "file.deletion_failed",
		)
	}
}

func (c *Client) cleanupScannedMails(mails []*scannedMail) {
	for _, mail := range mails {
		c.removeTempMail(mail)
	}
}

// replaceWithModifiedMails uploads mails to the spam or inbox mailbox, depending on their
// spam score.
// The original email is moved to the backup mailbox.
// It returns an UIDSet of all successfully uploaded mails.
// When errors happen, an error **and** a non-empty UIDSet can be returned.
func (c *Client) replaceWithModifiedMails(ctx context.Context, mails []*scannedMail) error {
	var errs []error

	for i, mail := range mails {
		if err := ctx.Err(); err != nil {
			c.cleanupScannedMails(mails[i:])
			return err
		}

		var mbox string

		logger := c.logger.With(
			"mail.subject", mail.Envelope.Subject,
			"mail.uid", mail.UID,
		)

		// TODO: support deleting emails from the mailbox, when backupMailbox is
		// empty instead of keeping a copy of the original, deleting
		// must happen after appendMail!
		err := c.clt.Move([]uint32{mail.UID}, c.backupMailbox)
		if err != nil {
			c.removeTempMail(mail)
			errs = append(errs, fmt.Errorf(
				"moving mail (%d) (%s) to backup mailbox %s failed: %w",
				mail.UID, mail.Envelope.Subject, c.backupMailbox, err,
			))

			continue
		}

		if c.isSpam(mail.CheckResult) {
			mbox = c.spamMailbox
		} else {
			mbox = c.inboxMailbox
		}

		err = c.clt.Upload(mail.Path, mbox, mail.Envelope.Date)
		if err != nil {
			c.removeTempMail(mail)
			errs = append(errs, fmt.Errorf(
				"uploading email %d (%s) (%s) to %s failed: %w",
				mail.UID, mail.Envelope.Subject, mail.Path, mbox, err,
			))
			logger.Warn(
				"uploading scanned email to inbox failed, please find the original email in the backup mailbox!",
				"event", "imap.msg_append_failed",
				"filepath", mail.Path,
				"mailbox.backup", c.backupMailbox,
				"mailbox.inbox", c.inboxMailbox,
			)

			continue
		}

		c.removeTempMail(mail)

		logger.Info("moved message to backup mailbox and uploaded modified message with scan results to inbox")
	}

	return errors.Join(errs...)
}

func (c *Client) downloadAndScan(ctx context.Context, msg *imapclt.Message) (*scannedMail, error) {
	tmpFile, err := os.CreateTemp(
		c.tempDir,
		"rspamd-iscan-mail-"+strconv.Itoa(int(msg.UID)),
	)
	if err != nil {
		return nil, fmt.Errorf("creating temporary file failed: %w", err)
	}

	errCleanupfn := func() {
		_ = tmpFile.Close()

		if c.keepTempFiles {
			return
		}

		if err := os.Remove(tmpFile.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
			c.logger.Error("deleting temporary file failed",
				"error", err, "filepath", tmpFile.Name(),
				"event", "file.deletion_failed")
		}
	}

	if err := ctx.Err(); err != nil {
		errCleanupfn()
		return nil, err
	}

	_, err = io.Copy(tmpFile, msg.Message)
	if err != nil {
		errCleanupfn()
		return nil, fmt.Errorf("downloading imap message to disk failed: %w", err)
	}

	env := &msg.Envelope
	logger := c.logger.With("mail.subject", env.Subject, "mail.uid", msg.UID)
	logger.Debug(
		"downloaded imap message",
		"filepath", tmpFile.Name(),
		"mail.envelope.message_id", env.MessageID,
		"mail.envelope.from", env.From,
		"mail.envelope.recipients", env.Recipients,
	)

	_, err = tmpFile.Seek(0, 0)
	if err != nil {
		errCleanupfn()
		return nil, fmt.Errorf("setting %q file position to beginning failed: %w", tmpFile.Name(), err)
	}
	// TODO: retry Check if it failed with a temporary error
	checkCtx, cancel := context.WithTimeout(ctx, c.rspamdTimeout)
	scanResult, err := c.rspamc.Check(checkCtx, tmpFile)
	cancel()
	if err != nil {
		errCleanupfn()
		return nil, err
	}

	if err := tmpFile.Close(); err != nil {
		errCleanupfn()
		return nil, fmt.Errorf("closing file of downloaded mail failed: %w", err)
	}

	if err := ctx.Err(); err != nil {
		errCleanupfn()
		return nil, err
	}

	if scanResult.Subject != "" && scanResult.Subject != env.Subject {
		err := mail.ReplaceHeader(
			tmpFile.Name(),
			mail.Header{Name: "Subject", Body: scanResult.Subject},
		)
		if err != nil {
			errCleanupfn()
			return nil, fmt.Errorf("rewriting subject failed: %w", err)
		}

		logger.Debug(
			"rewrote mail subject",
			"mail.subject.old", env.Subject,
			"mail.subject.new", scanResult.Subject,
		)
	}

	err = addScanResultHeaders(tmpFile.Name(), scanResult)
	if err != nil {
		errCleanupfn()
		return nil, fmt.Errorf("adding scan result headers to local mail copy failed: %w", err)
	}

	logger.Info(
		"message scanned",
		"scan.score", scanResult.Score, "scan.is_spam", c.isSpam(scanResult),
	)

	return &scannedMail{
		Path:        tmpFile.Name(),
		UID:         msg.UID,
		Envelope:    env,
		CheckResult: scanResult,
	}, nil
}

func (c *Client) ProcessScanBox() error {
	return c.runIMAPPhase(c.ctx, c.processScanBox)
}

func (c *Client) processScanBox(ctx context.Context) error {
	var scannedMails []*scannedMail
	var malformedMailsUIDs []uint32
	var errs []error

	logger := c.logger.With("mailbox.source", c.scanMailbox)
	logger.Info("processing scan box")

	for msg, err := range c.clt.Messages(c.scanMailbox) {
		if ctxErr := ctx.Err(); ctxErr != nil {
			c.cleanupScannedMails(scannedMails)
			return ctxErr
		}

		if err != nil {
			if errMalformed, ok := errors.AsType[*imapclt.ErrMalformedMsg](err); ok {
				logger.Warn(
					"email is malformed, skipping scan",
					"mail.uid", errMalformed.UID,
					"error", err,
					"event", "imap.msg_malformed",
				)
				malformedMailsUIDs = append(malformedMailsUIDs, errMalformed.UID)
				continue
			}

			c.cleanupScannedMails(scannedMails)
			return fmt.Errorf("fetching messages from scanbox failed: %w", err)
		}

		sm, err := c.downloadAndScan(ctx, msg)
		if err != nil {
			// TODO: abort on local tmpfile errors immediately,
			// unlikely that the following mail won't encounter the
			// same issue
			errs = append(errs, err)
			break
		}

		scannedMails = append(scannedMails, sm)
	}

	if err := ctx.Err(); err != nil {
		c.cleanupScannedMails(scannedMails)
		return err
	}

	err := c.replaceWithModifiedMails(ctx, scannedMails)
	if err != nil {
		errs = append(errs, err)
	}

	if len(malformedMailsUIDs) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}

		err = c.clt.Move(malformedMailsUIDs, c.inboxMailbox)
		if err != nil {
			errs = append(errs, fmt.Errorf("moving malformed mails failed: %w", err))
		}

		logger.Info("skipped scanning of malformed emails, moved mails to inbox",
			"count", len(malformedMailsUIDs))
	}

	c.cntProcessedMails.Add(uint64(len(scannedMails)))

	return errors.Join(errs...)
}

func (c *Client) connectionDone() <-chan struct{} {
	if client, ok := c.clt.(interface{ Done() <-chan struct{} }); ok {
		return client.Done()
	}

	return nil
}

// Monitor monitors the ScanMailbox for new messages and periodically
// processes the learning mailboxes. It blocks until an error occurs or Stop is
// called.
func (c *Client) Monitor() error {
	c.runMu.Lock()
	if c.ctx.Err() != nil {
		c.runMu.Unlock()
		return nil
	}
	c.wgRun.Add(1)
	c.runMu.Unlock()
	defer c.wgRun.Done()

	if err := c.runOnce(c.ctx); err != nil {
		if c.ctx.Err() != nil {
			return nil
		}
		return err
	}

	lastLearnAt := time.Now()

	for {
		if c.ctx.Err() != nil {
			return nil
		}

		eventCh, stop, err := c.startMonitor(c.ctx)
		if err != nil {
			if c.ctx.Err() != nil {
				return nil
			}
			return err
		}

		learnDelay := max(c.learnInterval-time.Since(lastLearnAt), 0)
		learnTimer := time.NewTimer(learnDelay)
		// A quiet IDLE connection has no application-level deadline in
		// go-imap, so periodically stop and restart it.
		idleTimer := time.NewTimer(c.idleTimeout)

		c.logger.Debug("waiting for mailbox update events")
		var monitorErr error
		stopped := false
		stopMonitor := func() error {
			if stopped {
				return nil
			}
			stopped = true
			return c.stopIDLE(stop)
		}

		select {
		case <-c.ctx.Done():
			_ = stopMonitor()
			return nil

		case <-c.connectionDone():
			_ = stopMonitor()
			if c.ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("imap connection closed while monitoring: %w", net.ErrClosed)

		case <-idleTimer.C:
			if err := stopMonitor(); err != nil {
				if c.ctx.Err() != nil {
					return nil
				}
				return err
			}
			c.logger.Debug("imap idle lease expired, restarting idle monitor")

		case <-learnTimer.C:
			if err := stopMonitor(); err != nil {
				if c.ctx.Err() != nil {
					return nil
				}
				return err
			}

			c.logger.Debug("periodic timer expired, learning ham, spam and checking the scan mailbox")
			if err := c.runPeriodicPass(c.ctx); err != nil {
				if c.ctx.Err() != nil {
					return nil
				}
				return err
			}
			lastLearnAt = time.Now()

		case ev, ok := <-eventCh:
			if !ok {
				_ = stopMonitor()
				if c.ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("imap monitor event channel closed: %w", net.ErrClosed)
			}

			if err := stopMonitor(); err != nil {
				if c.ctx.Err() != nil {
					return nil
				}
				return err
			}
			if ev.NewMsgCount == 0 {
				c.logger.Debug("ignoring MailboxUpdate, no new messages")
			} else if err := c.runIMAPPhase(c.ctx, c.processScanBox); err != nil {
				monitorErr = err
			}
		}

		if !learnTimer.Stop() {
			select {
			case <-learnTimer.C:
			default:
			}
		}
		if !idleTimer.Stop() {
			select {
			case <-idleTimer.C:
			default:
			}
		}

		if c.ctx.Err() != nil {
			return nil
		}
		if monitorErr != nil {
			return monitorErr
		}
	}
}

type monitorStart struct {
	events <-chan *imapclt.EventNewMessages
	stop   func() error
	err    error
}

func (c *Client) startMonitor(ctx context.Context) (<-chan *imapclt.EventNewMessages, func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	opCtx, cancel := context.WithTimeout(ctx, c.operationTimeout)
	defer cancel()

	result := make(chan monitorStart, 1)
	go func() {
		events, stop, err := c.clt.Monitor(c.scanMailbox)
		result <- monitorStart{events: events, stop: stop, err: err}
	}()

	select {
	case start := <-result:
		return start.events, start.stop, start.err
	case <-opCtx.Done():
		select {
		case start := <-result:
			return start.events, start.stop, start.err
		default:
		}
		_ = c.closeTransport()
		return nil, nil, opCtx.Err()
	}
}

func (c *Client) stopIDLE(stop func() error) error {
	if stop == nil {
		return nil
	}

	result := make(chan error, 1)
	go func() {
		result <- stop()
	}()

	timer := time.NewTimer(c.shutdownTimeout)
	defer timer.Stop()

	select {
	case err := <-result:
		return err
	case <-timer.C:
		_ = c.closeTransport()
		resultTimer := time.NewTimer(c.shutdownTimeout)
		defer resultTimer.Stop()
		select {
		case err := <-result:
			return err
		case <-resultTimer.C:
			return context.DeadlineExceeded
		}
	}
}

// closeTransport interrupts go-imap immediately; Close waits for its decoder,
// so the wait itself is bounded here.
func (c *Client) closeTransport() error {
	if c.clt == nil {
		return nil
	}

	c.transportCloseOnce.Do(func() {
		go func() {
			c.transportCloseErr = c.clt.Close()
			close(c.transportCloseDone)
		}()
	})

	timer := time.NewTimer(c.shutdownTimeout)
	defer timer.Stop()

	select {
	case <-c.transportCloseDone:
		return c.transportCloseErr
	case <-timer.C:
		return context.DeadlineExceeded
	}
}

// runIMAPPhase bounds a phase that may block in go-imap. go-imap has no
// context-aware waits, so a timeout must close and discard the connection.
func (c *Client) runIMAPPhase(ctx context.Context, fn func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	opCtx, cancel := context.WithTimeout(ctx, c.operationTimeout)
	defer cancel()

	result := make(chan error, 1)
	go func() {
		result <- fn(opCtx)
	}()

	select {
	case err := <-result:
		return err
	case <-opCtx.Done():
		select {
		case err := <-result:
			return err
		default:
		}
		_ = c.closeTransport()

		timer := time.NewTimer(c.shutdownTimeout)
		defer timer.Stop()
		select {
		case err := <-result:
			if err != nil {
				return errors.Join(opCtx.Err(), err)
			}
			return opCtx.Err()
		case <-timer.C:
			return opCtx.Err()
		}
	}
}

func (c *Client) runOnce(ctx context.Context) error {
	if err := c.runIMAPPhase(ctx, c.processHam); err != nil {
		return fmt.Errorf("learning ham failed: %w", err)
	}

	if err := c.runIMAPPhase(ctx, c.processSpam); err != nil {
		return fmt.Errorf("learning spam failed: %w", err)
	}

	if err := c.runIMAPPhase(ctx, c.processScanBox); err != nil {
		return err
	}

	return nil
}

func (c *Client) runPeriodicPass(ctx context.Context) error {
	if err := c.runIMAPPhase(ctx, c.processScanBox); err != nil {
		return err
	}

	if err := c.runIMAPPhase(ctx, c.processHam); err != nil {
		return err
	}

	return c.runIMAPPhase(ctx, c.processSpam)
}

// RunOnce processes all mails in the ham, spam and scan mailboxes once.
func (c *Client) RunOnce() error {
	return c.runOnce(c.ctx)
}

// Stop cancels processing, interrupts the IMAP transport, and then waits for
// the monitor goroutine to finish.
func (c *Client) Stop() error {
	var err error

	c.stopOnce.Do(func() {
		c.runMu.Lock()
		c.cancel()
		c.runMu.Unlock()

		err = c.closeTransport()

		waitResult := make(chan struct{})
		go func() {
			c.wgRun.Wait()
			close(waitResult)
		}()

		timer := time.NewTimer(c.shutdownTimeout)
		defer timer.Stop()
		select {
		case <-waitResult:
		case <-timer.C:
			err = errors.Join(err, context.DeadlineExceeded)
		}
	})

	return err
}
