package imapclt

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestConnectContextClosesStalledStartTLSHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		accepted <- conn

		_, _ = fmt.Fprint(conn, "* OK greeting\r\n")
		reader := bufio.NewReader(conn)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				return
			}
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			tag := fields[0]
			switch {
			case strings.Contains(strings.ToUpper(line), "CAPABILITY"):
				_, _ = fmt.Fprintf(conn, "%s OK CAPABILITY IMAP4rev1 STARTTLS\r\n", tag)
			case strings.Contains(strings.ToUpper(line), "STARTTLS"):
				_, _ = fmt.Fprintf(conn, "%s OK begin TLS\r\n", tag)
				continue
			default:
				_, _ = fmt.Fprintf(conn, "%s OK\r\n", tag)
			}
		}
	}()

	client := NewClient(&Config{Address: listener.Addr().String()})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err = client.ConnectContext(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected STARTTLS deadline, got %v", err)
	}

	select {
	case <-serverDone:
	case <-time.After(time.Second):
		select {
		case conn := <-accepted:
			_ = conn.Close()
		default:
		}
		t.Fatal("server did not observe the client closing the connection")
	}
}

func TestConnectContextClosesStalledServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
			buf := make([]byte, 1)
			for {
				if _, readErr := conn.Read(buf); readErr != nil {
					_ = conn.Close()
					return
				}
			}
		}
	}()

	client := NewClient(&Config{Address: listener.Addr().String()})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err = client.ConnectContext(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected connection deadline, got %v", err)
	}

	select {
	case <-serverDone:
	case <-time.After(time.Second):
		select {
		case conn := <-accepted:
			_ = conn.Close()
		default:
		}
		t.Fatal("server did not observe the client closing the connection")
	}
}
