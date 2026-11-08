package smtp_test

// BDAT runs Session.Data on its own goroutine and returns to the command loop
// between chunks, so a command that aborts the transfer reaches the session
// while Data may still be running (Open-Email/smtp-in#204). No other Session
// callback may overlap that Data call, and the call's result belongs to its
// own transaction.

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

// bdatUnwindBackend's Data drains the message. When the transfer is aborted
// it takes unwind to return, like a backend finishing its bookkeeping after
// the reader fails; a message that arrives whole takes deliver. Every
// callback is logged in order.
type bdatUnwindBackend struct {
	unwind  time.Duration
	deliver time.Duration
	// closeInData makes Data close the connection itself once the first
	// chunk arrives, as a backend that gives up on a client may.
	closeInData bool

	mu     sync.Mutex
	events []string
}

func (b *bdatUnwindBackend) log(event string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, event)
}

func (b *bdatUnwindBackend) logged() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.events)
}

func (b *bdatUnwindBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &bdatUnwindSession{backend: b, conn: c}, nil
}

type bdatUnwindSession struct {
	backend *bdatUnwindBackend
	conn    *smtp.Conn
}

func (s *bdatUnwindSession) Reset()        { s.backend.log("reset") }
func (s *bdatUnwindSession) Logout() error { s.backend.log("logout"); return nil }
func (*bdatUnwindSession) Mail(ctx context.Context, from string, opts *smtp.MailOptions) error {
	return nil
}
func (*bdatUnwindSession) Rcpt(ctx context.Context, to string, opts *smtp.RcptOptions) error {
	return nil
}
func (s *bdatUnwindSession) Data(ctx context.Context, r io.Reader) error {
	if s.backend.closeInData {
		io.ReadFull(r, make([]byte, 1))
		s.conn.Close()
		s.backend.log("data returned")
		return smtp.ErrDataReset
	}
	_, err := io.Copy(io.Discard, r)
	if err != nil {
		time.Sleep(s.backend.unwind)
	} else {
		time.Sleep(s.backend.deliver)
	}
	s.backend.log("data returned")
	return err
}

type bdatClient struct {
	t      *testing.T
	server *smtp.Server
	conn   net.Conn
	br     *bufio.Reader
}

func newBdatClient(t *testing.T, be *bdatUnwindBackend, fn ...serverConfigureFunc) *bdatClient {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := smtp.NewServer(be)
	server.Domain = "localhost"
	for _, f := range fn {
		f(server)
	}
	go server.Serve(l)
	t.Cleanup(func() { server.Close() })

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	c := &bdatClient{t: t, server: server, conn: conn, br: bufio.NewReader(conn)}
	c.expect("220")
	c.cmd("EHLO client.example.com", "250")
	return c
}

// expect reads reply lines up to the final one, which must carry code.
func (c *bdatClient) expect(code string) {
	c.t.Helper()
	for {
		line, err := c.br.ReadString('\n')
		if err != nil {
			c.t.Fatalf("want %s: %v", code, err)
		}
		if strings.HasPrefix(line, code+"-") {
			continue
		}
		if !strings.HasPrefix(line, code+" ") {
			c.t.Fatalf("want %s, got %q", code, strings.TrimSpace(line))
		}
		return
	}
}

func (c *bdatClient) cmd(line, code string) {
	c.t.Helper()
	io.WriteString(c.conn, line+"\r\n")
	c.expect(code)
}

// startBdat opens a transaction and sends its first, non-final chunk, which
// starts the Data goroutine.
func (c *bdatClient) startBdat() {
	c.t.Helper()
	c.cmd("MAIL FROM:<sender@example.com>", "250")
	c.cmd("RCPT TO:<rcpt@example.com>", "250")
	io.WriteString(c.conn, "BDAT 1\r\nx")
	c.expect("250")
}

// awaitBefore waits until both events are logged and fails unless first was
// logged before then.
func awaitBefore(t *testing.T, be *bdatUnwindBackend, first, then string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		events := be.logged()
		i, j := slices.Index(events, first), slices.Index(events, then)
		if i >= 0 && j >= 0 {
			if i > j {
				t.Fatalf("%s ran while Data was still running: %v", then, events)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("want %q and %q, got %v", first, then, events)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestBdatAbort_CallbacksWaitForData(t *testing.T) {
	for _, tc := range []struct {
		name     string
		callback string
		config   []serverConfigureFunc
		abort    func(c *bdatClient)
	}{
		{name: "RSET", callback: "reset", abort: func(c *bdatClient) { c.cmd("RSET", "250") }},
		// STARTTLS logs the session out so the post-TLS greeting starts a new
		// one. A repeated greeting during BDAT is refused without touching the
		// transfer; see TestGreetingDuringBDATLeavesTransferIntact.
		{name: "STARTTLS", callback: "logout", config: []serverConfigureFunc{withTLS}, abort: func(c *bdatClient) {
			c.cmd("STARTTLS", "220")
			if err := tls.Client(c.conn, &tls.Config{InsecureSkipVerify: true}).Handshake(); err != nil {
				c.t.Fatalf("handshake: %v", err)
			}
		}},
		{name: "client disconnect", callback: "logout", abort: func(c *bdatClient) { c.conn.Close() }},
		{name: "Server.Close", callback: "logout", abort: func(c *bdatClient) { c.server.Close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			be := &bdatUnwindBackend{unwind: 100 * time.Millisecond}
			c := newBdatClient(t, be, tc.config...)
			c.startBdat()
			tc.abort(c)
			awaitBefore(t, be, "data returned", tc.callback)
		})
	}
}

// The aborted Data call's result must not answer the next transaction's BDAT
// LAST: that would bounce or defer a message whose own Data is still running,
// and strand that Data call on a full result channel.
func TestBdatAbort_NextTransactionGetsItsOwnResult(t *testing.T) {
	be := &bdatUnwindBackend{unwind: 100 * time.Millisecond, deliver: 300 * time.Millisecond}
	c := newBdatClient(t, be)
	c.startBdat()
	c.cmd("RSET", "250")

	c.cmd("MAIL FROM:<sender@example.com>", "250")
	c.cmd("RCPT TO:<rcpt@example.com>", "250")
	io.WriteString(c.conn, "BDAT 1 LAST\r\ny")
	c.expect("250")
}

// Close hands Logout to the Data goroutine rather than waiting for it, so a
// Data call that closes the connection itself does not wait for itself.
func TestBdatAbort_CloseFromDataDoesNotDeadlock(t *testing.T) {
	be := &bdatUnwindBackend{closeInData: true}
	c := newBdatClient(t, be)
	c.startBdatNoReply()
	awaitBefore(t, be, "data returned", "logout")
}

// startBdatNoReply is startBdat for a Data call that closes the connection:
// the chunk may never be answered.
func (c *bdatClient) startBdatNoReply() {
	c.t.Helper()
	c.cmd("MAIL FROM:<sender@example.com>", "250")
	c.cmd("RCPT TO:<rcpt@example.com>", "250")
	io.WriteString(c.conn, "BDAT 1\r\nx")
}
