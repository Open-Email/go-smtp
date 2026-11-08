package smtp

// Tests for the per-command context passed to Session.Mail/Rcpt/Data: how it
// is derived, when it is cancelled, and that transaction aborts and backend
// panics cannot strand it.

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

// ctxTestExpect reads reply lines until the final (non-continuation) line for
// the expected code and fails the test on anything else.
func ctxTestExpect(t *testing.T, br *bufio.Reader, code string) {
	t.Helper()
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("failed to read reply: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, code+"-") {
			continue
		}
		if !strings.HasPrefix(line, code) {
			t.Fatalf("expected reply %q, got %q", code, line)
		}
		return
	}
}

// ctxAbortSession simulates a backend blocked on upstream work during a BDAT
// transfer: it consumes the first chunk byte so the server can reply
// "250 Continue", then stops reading the message and waits solely on the
// per-command context — the only abort signal such a backend can observe.
type ctxAbortBackend struct {
	started chan struct{}
	result  chan error
}

func (b *ctxAbortBackend) NewSession(*Conn) (Session, error) {
	return &ctxAbortSession{backend: b}, nil
}

type ctxAbortSession struct{ backend *ctxAbortBackend }

func (*ctxAbortSession) Reset()        {}
func (*ctxAbortSession) Logout() error { return nil }
func (*ctxAbortSession) Mail(ctx context.Context, from string, opts *MailOptions) error {
	return nil
}
func (*ctxAbortSession) Rcpt(ctx context.Context, to string, opts *RcptOptions) error {
	return nil
}
func (s *ctxAbortSession) Data(ctx context.Context, r io.Reader) error {
	buf := make([]byte, 1)
	if _, err := io.ReadFull(r, buf); err != nil {
		s.backend.result <- err
		return err
	}
	s.backend.started <- struct{}{}
	select {
	case <-ctx.Done():
		s.backend.result <- nil
		return ctx.Err()
	case <-time.After(2 * time.Second):
		err := errors.New("per-command context was not cancelled")
		s.backend.result <- err
		return err
	}
}

// An RSET that aborts a BDAT transfer must cancel the per-command context:
// a backend stuck in upstream I/O never reads the message reader, so the
// pipe's ErrDataReset cannot reach it and the context is its only signal.
func TestBdatRset_CancelsCommandContext(t *testing.T) {
	backend := &ctxAbortBackend{
		started: make(chan struct{}, 1),
		result:  make(chan error, 1),
	}
	server := NewServer(backend)
	server.Domain = "example.com"

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	go server.handleConn(newConn(serverConn, server))

	clientConn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(clientConn)

	ctxTestExpect(t, br, "220")
	io.WriteString(clientConn, "EHLO client.example.com\r\n")
	ctxTestExpect(t, br, "250")
	io.WriteString(clientConn, "MAIL FROM:<sender@example.com>\r\n")
	ctxTestExpect(t, br, "250")
	io.WriteString(clientConn, "RCPT TO:<rcpt@example.com>\r\n")
	ctxTestExpect(t, br, "250")

	// Non-last chunk: spawns the data goroutine, which consumes the byte and
	// then blocks watching the context.
	io.WriteString(clientConn, "BDAT 1\r\nx")
	ctxTestExpect(t, br, "250")
	<-backend.started

	io.WriteString(clientConn, "RSET\r\n")
	ctxTestExpect(t, br, "250")

	select {
	case err := <-backend.result:
		if err != nil {
			t.Fatalf("RSET did not cancel the in-flight BDAT context: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("backend Data never returned after RSET")
	}
}

// ctxPanicSession hands the per-command context to the test and then panics,
// exercising the recover path in Conn.handle.
type ctxPanicBackend struct{ mailCtx chan context.Context }

func (b *ctxPanicBackend) NewSession(*Conn) (Session, error) {
	return &ctxPanicSession{backend: b}, nil
}

type ctxPanicSession struct{ backend *ctxPanicBackend }

func (*ctxPanicSession) Reset()        {}
func (*ctxPanicSession) Logout() error { return nil }
func (s *ctxPanicSession) Mail(ctx context.Context, from string, opts *MailOptions) error {
	s.backend.mailCtx <- ctx
	panic("ctx_test: backend panic during MAIL")
}
func (*ctxPanicSession) Rcpt(ctx context.Context, to string, opts *RcptOptions) error {
	return nil
}
func (*ctxPanicSession) Data(ctx context.Context, r io.Reader) error {
	return nil
}

// A backend panic is recovered by Conn.handle; the per-command context must
// still be cancelled once the command is over, or work the backend handed it
// to keeps running against a connection that already answered 421.
func TestBackendPanic_CancelsCommandContext(t *testing.T) {
	backend := &ctxPanicBackend{mailCtx: make(chan context.Context, 1)}
	server := NewServer(backend)
	server.Domain = "example.com"
	// The recover path logs the panic stack; that is this test's expected
	// behavior, not noise worth printing.
	server.ErrorLog = log.New(io.Discard, "", 0)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	go io.Copy(io.Discard, clientConn) // drain the 421 written by the recover path

	c := newConn(serverConn, server)
	c.setGreeting("client.example.com", "EHLO")
	session, err := backend.NewSession(c)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	c.swapSession(session)

	c.handle("MAIL", "FROM:<sender@example.com>")

	ctx := <-backend.mailCtx
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("per-command context was not cancelled after the backend panicked")
	}
}

// ctxFallbackSession implements Session but not LMTPSession, forcing an LMTP
// server's BDAT goroutine through the fallback branch that fans the Data
// error out to every recipient.
type ctxFallbackBackend struct{}

func (*ctxFallbackBackend) NewSession(*Conn) (Session, error) {
	return &ctxFallbackSession{}, nil
}

type ctxFallbackSession struct{}

func (*ctxFallbackSession) Reset()        {}
func (*ctxFallbackSession) Logout() error { return nil }
func (*ctxFallbackSession) Mail(ctx context.Context, from string, opts *MailOptions) error {
	return nil
}
func (*ctxFallbackSession) Rcpt(ctx context.Context, to string, opts *RcptOptions) error {
	return nil
}
func (s *ctxFallbackSession) Data(ctx context.Context, r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err // ErrDataReset once RSET closes the pipe
}

// Regression test for a data race: reset() nils c.recipients and
// c.bdatStatus under the connection lock while the BDAT goroutine's fallback
// branch reads them unlocked after Data returns. Fails under -race without
// the snapshot fix; the sleep gives the goroutine time to run its post-Data
// code while the test still owns the connection.
func TestBdatRset_NoStatusFallbackRace(t *testing.T) {
	server := NewServer(&ctxFallbackBackend{})
	server.LMTP = true
	server.Domain = "example.com"

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	go server.handleConn(newConn(serverConn, server))

	clientConn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(clientConn)

	ctxTestExpect(t, br, "220")
	io.WriteString(clientConn, "LHLO client.example.com\r\n")
	ctxTestExpect(t, br, "250")
	io.WriteString(clientConn, "MAIL FROM:<sender@example.com>\r\n")
	ctxTestExpect(t, br, "250")
	io.WriteString(clientConn, "RCPT TO:<rcpt@example.com>\r\n")
	ctxTestExpect(t, br, "250")

	io.WriteString(clientConn, "BDAT 1\r\nx")
	ctxTestExpect(t, br, "250")

	io.WriteString(clientConn, "RSET\r\n")
	ctxTestExpect(t, br, "250")

	time.Sleep(200 * time.Millisecond)
}

// ctxCaptureSession hands the test the context each command receives.
type ctxCaptureBackend struct{ mailCtx chan context.Context }

func (b *ctxCaptureBackend) NewSession(*Conn) (Session, error) {
	return &ctxCaptureSession{backend: b}, nil
}

type ctxCaptureSession struct{ backend *ctxCaptureBackend }

func (*ctxCaptureSession) Reset()        {}
func (*ctxCaptureSession) Logout() error { return nil }
func (s *ctxCaptureSession) Mail(ctx context.Context, from string, opts *MailOptions) error {
	s.backend.mailCtx <- ctx
	return nil
}
func (*ctxCaptureSession) Rcpt(ctx context.Context, to string, opts *RcptOptions) error {
	return nil
}
func (*ctxCaptureSession) Data(ctx context.Context, r io.Reader) error {
	return nil
}

type ctxTestBaseKey struct{}

// The per-command context must carry values from Server.BaseContext (it is
// derived from the connection context) and must be cancelled once the
// command has finished.
func TestCommandContext_BaseContextValuesAndCancel(t *testing.T) {
	backend := &ctxCaptureBackend{mailCtx: make(chan context.Context, 1)}
	server := NewServer(backend)
	server.Domain = "example.com"
	server.BaseContext = func(net.Listener) context.Context {
		return context.WithValue(context.Background(), ctxTestBaseKey{}, "present")
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(l)
	defer server.Close()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)

	ctxTestExpect(t, br, "220")
	io.WriteString(conn, "EHLO client.example.com\r\n")
	ctxTestExpect(t, br, "250")
	io.WriteString(conn, "MAIL FROM:<sender@example.com>\r\n")
	ctxTestExpect(t, br, "250")

	ctx := <-backend.mailCtx
	if v, _ := ctx.Value(ctxTestBaseKey{}).(string); v != "present" {
		t.Errorf("per-command context does not carry BaseContext values: got %q", v)
	}
	// The 250 is written after Mail returns, so by now the command is over.
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("per-command context was not cancelled after MAIL finished")
	}
}

// ctxShutdownSession consumes the whole DATA body, then blocks watching its
// context, emulating a backend mid-delivery when the server shuts down.
type ctxShutdownBackend struct {
	consumed chan struct{}
	result   chan error
}

func (b *ctxShutdownBackend) NewSession(*Conn) (Session, error) {
	return &ctxShutdownSession{backend: b}, nil
}

type ctxShutdownSession struct{ backend *ctxShutdownBackend }

func (*ctxShutdownSession) Reset()        {}
func (*ctxShutdownSession) Logout() error { return nil }
func (*ctxShutdownSession) Mail(ctx context.Context, from string, opts *MailOptions) error {
	return nil
}
func (*ctxShutdownSession) Rcpt(ctx context.Context, to string, opts *RcptOptions) error {
	return nil
}
func (s *ctxShutdownSession) Data(ctx context.Context, r io.Reader) error {
	if _, err := io.Copy(io.Discard, r); err != nil {
		s.backend.result <- err
		return err
	}
	s.backend.consumed <- struct{}{}
	select {
	case <-ctx.Done():
		s.backend.result <- nil
		return ctx.Err()
	case <-time.After(2 * time.Second):
		err := errors.New("per-command context was not cancelled")
		s.backend.result <- err
		return err
	}
}

// Server.Shutdown must cancel a per-command context that is in flight inside
// Session.Data, via the connection context it derives from.
func TestShutdown_CancelsInflightDataContext(t *testing.T) {
	backend := &ctxShutdownBackend{
		consumed: make(chan struct{}, 1),
		result:   make(chan error, 1),
	}
	server := NewServer(backend)
	server.Domain = "example.com"

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	go server.handleConn(newConn(serverConn, server))

	clientConn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(clientConn)

	ctxTestExpect(t, br, "220")
	io.WriteString(clientConn, "EHLO client.example.com\r\n")
	ctxTestExpect(t, br, "250")
	io.WriteString(clientConn, "MAIL FROM:<sender@example.com>\r\n")
	ctxTestExpect(t, br, "250")
	io.WriteString(clientConn, "RCPT TO:<rcpt@example.com>\r\n")
	ctxTestExpect(t, br, "250")
	io.WriteString(clientConn, "DATA\r\n")
	ctxTestExpect(t, br, "354")
	io.WriteString(clientConn, "hello\r\n.\r\n")
	<-backend.consumed

	shutdownDone := make(chan struct{})
	go func() {
		server.Shutdown(context.Background())
		close(shutdownDone)
	}()

	select {
	case err := <-backend.result:
		if err != nil {
			t.Fatalf("Shutdown did not cancel the in-flight Data context: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("backend Data never returned after Shutdown")
	}

	// Unblock Shutdown: read Data's reply, then drop the connection.
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("failed to read DATA reply: %v", err)
	}
	clientConn.Close()
	select {
	case <-shutdownDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown did not return after the connection closed")
	}
}
