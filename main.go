package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fho/rspamd-iscan/internal/config"
	"github.com/fho/rspamd-iscan/internal/imapclt"
	"github.com/fho/rspamd-iscan/internal/iscan"
	"github.com/fho/rspamd-iscan/internal/neterr"
	"github.com/fho/rspamd-iscan/internal/retry"
	"github.com/fho/rspamd-iscan/internal/rspamc"

	flag "github.com/spf13/pflag"
)

const (
	maxRetriesSameError = 10
)

var (
	version = "version-undefined"
	commit  = "commit-undefined"
)

type flags struct {
	cfgPath              string
	credentialsDirectory string
	printVersion         bool
	once                 bool
	dryRun               bool
}

func durationSeconds(seconds int, fallback time.Duration) time.Duration {
	if seconds <= 0 {
		return fallback
	}

	return time.Duration(seconds) * time.Second
}

func mustParseFlags() *flags {
	var result flags

	flag.StringVar(&result.cfgPath, "cfg-file", "/etc/rspamd-iscan/config.toml",
		"Path to the rspamd-iscan config file")
	flag.StringVar(&result.credentialsDirectory, "credentials-directory", os.Getenv("CREDENTIALS_DIRECTORY"),
		"Directory containing credential files (defaults to $CREDENTIALS_DIRECTORY)")
	flag.BoolVar(&result.printVersion, "version", false,
		"print the version and exit")
	flag.BoolVar(&result.once, "once", false,
		"processes all mails in the ham, spam and scan mailbox once and terminates",
	)
	flag.BoolVarP(&result.dryRun, "dry-run", "n", false,
		"simulates modifying operations on the IMAP server, also enables --once",
	)

	flag.Parse()

	if result.dryRun {
		result.once = true
	}

	return &result
}

func configureLogger(loglevel slog.Level) *slog.Logger {
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: loglevel,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// do not log timestamp, rspamd-iscan is normally run as
			// daemon, journald/syslog already adds timestamps
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})

	return slog.New(h)
}

var handledSignals = []os.Signal{syscall.SIGTERM, syscall.SIGINT}

func newIMAPClient(
	ctx context.Context,
	cfg *config.Config,
	flags *flags,
	logger *slog.Logger,
) (iscan.IMAPClient, error) {
	var clt iscan.IMAPClient

	imapCfg := imapclt.Config{
		Address:       cfg.ImapAddr,
		User:          cfg.ImapUser,
		Password:      cfg.ImapPassword,
		AllowInsecure: false,
		Logger:        logger,
		LogIMAPData:   cfg.LogIMAPData,
	}

	if flags.dryRun {
		fmt.Println("--dry-run enabled, IMAP mailboxes are not modified")
		clt = imapclt.NewDryClient(&imapCfg)
	} else {
		clt = imapclt.NewClient(&imapCfg)
	}

	connectCtx, cancel := context.WithTimeout(
		ctx,
		durationSeconds(cfg.IMAPOperationTimeoutSeconds, iscan.DefaultOperationTimeout),
	)
	defer cancel()

	var err error
	if connector, ok := clt.(interface{ ConnectContext(context.Context) error }); ok {
		err = connector.ConnectContext(connectCtx)
	} else {
		err = clt.Connect()
	}
	if err != nil {
		return nil, err
	}

	return clt, nil
}

func newIscanClient(
	ctx context.Context,
	cfg *config.Config,
	logger *slog.Logger,
	rspamc iscan.RspamdClient,
	imapClt iscan.IMAPClient,
) (*iscan.Client, error) {
	iscanCfg := iscan.Config{
		ScanMailbox:             cfg.ScanMailbox,
		InboxMailbox:            cfg.InboxMailbox,
		HamMailbox:              cfg.HamMailbox,
		SpamMailboxName:         cfg.SpamMailbox,
		UndetectedMailboxName:   cfg.UndetectedMailbox,
		BackupMailbox:           cfg.BackupMailbox,
		SpamTreshold:            cfg.SpamThreshold,
		TempDir:                 cfg.TempDir,
		KeepTempFiles:           cfg.KeepTempFiles,
		MarkLearnedAsSpamAsRead: cfg.MarkLearnedAsSpamAsRead,
		Logger:                  logger,
		Rspamc:                  rspamc,
		IMAPClient:              imapClt,
		Context:                 ctx,
		OperationTimeout:        durationSeconds(cfg.IMAPOperationTimeoutSeconds, iscan.DefaultOperationTimeout),
		RspamdTimeout:           durationSeconds(cfg.RspamdTimeoutSeconds, iscan.DefaultRspamdTimeout),
		IdleTimeout:             durationSeconds(cfg.IMAPIdleTimeoutSeconds, iscan.DefaultIdleTimeout),
		ShutdownTimeout:         durationSeconds(cfg.ShutdownTimeoutSeconds, iscan.DefaultShutdownTimeout),
	}

	return iscan.NewClient(&iscanCfg)
}

func runOnceAndTerminate(
	ctx context.Context,
	cfg *config.Config,
	flags *flags,
	logger *slog.Logger,
	rspamc iscan.RspamdClient,
) error {
	imapClt, err := newIMAPClient(ctx, cfg, flags, logger)
	if err != nil {
		return fmt.Errorf("creating imap client failed: %w", err)
	}

	clt, err := newIscanClient(ctx, cfg, logger, rspamc, imapClt)
	if err != nil {
		_ = imapClt.Close()
		return fmt.Errorf("creating iscan client failed %w", err)
	}
	defer func() {
		_ = clt.Stop()
	}()

	return clt.RunOnce()
}

func monitor(
	ctx context.Context,
	cfg *config.Config,
	flags *flags,
	logger *slog.Logger,
	rspamc iscan.RspamdClient,
) error {
	imapClt, err := newIMAPClient(ctx, cfg, flags, logger)
	if err != nil {
		return fmt.Errorf("creating imap client failed: %w", err)
	}

	clt, err := newIscanClient(ctx, cfg, logger, rspamc, imapClt)
	if err != nil {
		_ = imapClt.Close()
		return err
	}

	err = clt.Monitor()
	_ = clt.Stop()
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("monitoring imap mailboxes failed: %w", err)
	}

	return nil
}

func toSlogLevel(lvl string) (slog.Level, error) {
	switch strings.ToLower(lvl) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unsupported log level: %q", lvl)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), handledSignals...)
	defer stop()

	flags := mustParseFlags()
	if flags.printVersion {
		fmt.Printf("rspamd-iscan %s (%s)\n", version, commit)
		return nil
	}

	cfg, err := config.FromFile(flags.cfgPath)
	if err != nil {
		return fmt.Errorf("loading config failed: %w", err)
	}

	loglvl, err := toSlogLevel(cfg.LogLevel)
	if err != nil {
		return err
	}
	logger := configureLogger(loglvl)

	if flags.credentialsDirectory != "" {
		if err := cfg.LoadCredentialsFromDirectory(flags.credentialsDirectory); err != nil {
			return fmt.Errorf("loading credentials from directory (%s) failed: %w", flags.credentialsDirectory, err)
		}
	}

	fmt.Print(cfg.String())

	// TODO: allow passing all attrs as single URL to rspamc http client
	rspamc := rspamc.New(
		logger,
		cfg.RspamdURL,
		cfg.RspamdPassword,
		durationSeconds(cfg.RspamdTimeoutSeconds, iscan.DefaultRspamdTimeout),
	)

	if flags.once {
		logger.Info("running once and terminating (--once)")
		err := runOnceAndTerminate(ctx, cfg, flags, logger, rspamc)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}

	logger.Info("monitoring IMAP mailboxes continuously, retrying on retryable errors",
		"max_retries_same_error", maxRetriesSameError)

	retryRunner := retry.Runner{
		Context:             ctx,
		Fn:                  func() error { return monitor(ctx, cfg, flags, logger, rspamc) },
		IsRetryable:         neterr.IsRetryableError,
		MaxRetriesSameError: maxRetriesSameError,
		RetryIntervals: []time.Duration{
			3 * time.Second,
			30 * time.Second,
			time.Minute,
			3 * time.Minute,
		},
		Logger:   logger,
		ErrorKey: neterr.RetryKey,
	}

	return retryRunner.Run()
}

func main() {
	if err := run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
