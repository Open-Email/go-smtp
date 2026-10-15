package smtp_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

// After a non-final BDAT chunk the line-length limit must still apply to the
// next command read; otherwise a client can stream an endless line and force
// unbounded buffering.
func TestServer_LineLimitAppliesAfterBDATChunk(t *testing.T) {
	_, s, c, scanner, _ := testServerEhlo(t)
	defer s.Close()
	defer c.Close()

	c.SetDeadline(time.Now().Add(10 * time.Second))

	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid MAIL response:", scanner.Text())
	}

	io.WriteString(c, "RCPT TO:<root@gchq.gov.uk>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid RCPT response:", scanner.Text())
	}

	io.WriteString(c, "BDAT 8\r\n")
	io.WriteString(c, "Hey <3\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid BDAT response:", scanner.Text())
	}

	// The next command line exceeds MaxLineLength (default 2000); the server
	// must reject it instead of buffering it without bound.
	io.WriteString(c, strings.Repeat("a", 5000)+"\r\n")
	scanner.Scan()
	if !strings.Contains(scanner.Text(), "Too long line") {
		t.Fatal("Expected too-long-line rejection, got:", scanner.Text())
	}
}

// An oversized BDAT chunk must be discarded with the line-length limit
// disabled: the chunk is binary data, and aborting the discard mid-chunk
// desyncs the stream so chunk bytes get parsed as commands.
func TestServer_BDATOversizedChunkDiscard(t *testing.T) {
	_, s, c, scanner, _ := testServerEhlo(t, func(s *smtp.Server) {
		s.MaxMessageBytes = 10
	})
	defer s.Close()
	defer c.Close()

	c.SetDeadline(time.Now().Add(10 * time.Second))

	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid MAIL response:", scanner.Text())
	}

	io.WriteString(c, "RCPT TO:<root@gchq.gov.uk>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid RCPT response:", scanner.Text())
	}

	// One long line, no newline, longer than MaxLineLength. The 552 is
	// written before the server starts discarding the chunk, so wait for it
	// before sending the payload.
	payload := strings.Repeat("a", 5000)
	io.WriteString(c, fmt.Sprintf("BDAT %d\r\n", len(payload)))
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "552 ") {
		t.Fatal("Invalid BDAT response:", scanner.Text())
	}
	io.WriteString(c, payload)

	// The whole chunk must have been consumed: the next command must parse.
	io.WriteString(c, "NOOP\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Stream desynced after oversized chunk, got:", scanner.Text())
	}
}

func TestServer_DoubleMailFrom(t *testing.T) {
	_, s, c, scanner, _ := testServerEhlo(t)
	defer s.Close()
	defer c.Close()

	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid MAIL response:", scanner.Text())
	}

	// RFC 5321 section 4.1.1.2: a nested MAIL is a bad sequence of commands.
	io.WriteString(c, "MAIL FROM:<other@nsa.gov>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "503 ") {
		t.Fatal("Invalid second MAIL response:", scanner.Text())
	}

	// RSET clears the transaction and MAIL is allowed again.
	io.WriteString(c, "RSET\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid RSET response:", scanner.Text())
	}
	io.WriteString(c, "MAIL FROM:<other@nsa.gov>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid MAIL response after RSET:", scanner.Text())
	}
}

func TestServer_AuthFailureLimit(t *testing.T) {
	_, s, c, scanner, _ := testServerEhlo(t)
	defer s.Close()
	defer c.Close()

	c.SetDeadline(time.Now().Add(10 * time.Second))

	badCreds := base64.StdEncoding.EncodeToString([]byte("\x00username\x00wrong"))
	for i := 0; i < 3; i++ {
		io.WriteString(c, "AUTH PLAIN "+badCreds+"\r\n")
		scanner.Scan()
		if !strings.HasPrefix(scanner.Text(), "454 ") {
			t.Fatal("Invalid AUTH response:", scanner.Text())
		}
	}

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "421 ") {
		t.Fatal("Expected 421 after too many AUTH failures, got:", scanner.Text())
	}
	if scanner.Scan() {
		t.Fatal("Expected connection to be closed, got:", scanner.Text())
	}
}

// A failed read during the SASL exchange must terminate the connection with
// the same classification the serve loop uses. Silently aborting AUTH used to
// desync the session: the remainder of an over-long SASL response line would
// be parsed as SMTP commands.
func TestServer_AuthReadErrorClosesConnection(t *testing.T) {
	_, s, c, scanner, _ := testServerEhlo(t)
	defer s.Close()
	defer c.Close()

	c.SetDeadline(time.Now().Add(10 * time.Second))

	io.WriteString(c, "AUTH PLAIN\r\n")
	scanner.Scan()
	if scanner.Text() != "334 " {
		t.Fatal("Invalid AUTH response:", scanner.Text())
	}

	// A SASL response line exceeding MaxLineLength (default 2000). Exactly
	// MaxLineLength+2 bytes and no newline, so the server errors with nothing
	// left unread — a clean close (FIN, not RST) that the 500 reply survives.
	io.WriteString(c, strings.Repeat("a", 2002))
	scanner.Scan()
	if !strings.Contains(scanner.Text(), "Too long line") {
		t.Fatal("Expected too-long-line rejection, got:", scanner.Text())
	}
	if scanner.Scan() {
		t.Fatal("Expected connection to be closed, got:", scanner.Text())
	}
}

func TestServer_MaxConnections(t *testing.T) {
	_, s, c, scanner := testServerGreeted(t, func(s *smtp.Server) {
		s.MaxConnections = 1
	})
	defer s.Close()
	defer c.Close()

	addr := c.RemoteAddr().String()

	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c2.SetDeadline(time.Now().Add(10 * time.Second))
	scanner2 := bufio.NewScanner(c2)
	scanner2.Scan()
	if !strings.HasPrefix(scanner2.Text(), "421 ") {
		t.Fatal("Expected 421 for connection above the limit, got:", scanner2.Text())
	}
	if scanner2.Scan() {
		t.Fatal("Expected rejected connection to be closed, got:", scanner2.Text())
	}
	c2.Close()

	// The first connection is unaffected.
	io.WriteString(c, "NOOP\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid NOOP response:", scanner.Text())
	}

	// Closing the first connection frees its slot.
	c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c3, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c3.SetDeadline(time.Now().Add(10 * time.Second))
		scanner3 := bufio.NewScanner(c3)
		if !scanner3.Scan() {
			t.Fatal("No response on new connection")
		}
		line := scanner3.Text()
		c3.Close()

		if strings.HasPrefix(line, "220 ") {
			break
		}
		if !strings.HasPrefix(line, "421 ") {
			t.Fatal("Unexpected greeting:", line)
		}
		if time.Now().After(deadline) {
			t.Fatal("Connection slot was never freed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// CR in backend-provided response text must not reach the wire: \r\n inside a
// message would otherwise produce \r\r\n after the multi-line split.
func TestServer_ResponseTextCRSanitized(t *testing.T) {
	be, s, c, scanner, _ := testServerEhlo(t)
	defer s.Close()
	defer c.Close()

	be.userErr = &smtp.SMTPError{
		Code:         451,
		EnhancedCode: smtp.EnhancedCode{4, 0, 0},
		Message:      "temporary\r\nfailure",
	}

	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	if scanner.Text() != "451-temporary" {
		t.Fatalf("Invalid first response line: %q", scanner.Text())
	}
	scanner.Scan()
	if scanner.Text() != "451 4.0.0 failure" {
		t.Fatalf("Invalid last response line: %q", scanner.Text())
	}
}

type ctxSession struct{}

func (ctxSession) Reset()        {}
func (ctxSession) Logout() error { return nil }
func (ctxSession) Mail(ctx context.Context, from string, opts *smtp.MailOptions) error {
	return nil
}
func (ctxSession) Rcpt(ctx context.Context, to string, opts *smtp.RcptOptions) error {
	return nil
}
func (ctxSession) Data(ctx context.Context, r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}

type baseCtxKey struct{}

func testCtxServer(t *testing.T) (s *smtp.Server, c net.Conn, ctx context.Context) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctxs := make(chan context.Context, 1)
	s = smtp.NewServer(smtp.BackendFunc(func(conn *smtp.Conn) (smtp.Session, error) {
		ctxs <- conn.Context()
		return ctxSession{}, nil
	}))
	s.Domain = "localhost"
	s.BaseContext = func(l net.Listener) context.Context {
		return context.WithValue(context.Background(), baseCtxKey{}, "base")
	}
	go s.Serve(l)

	c, err = net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))

	scanner := bufio.NewScanner(c)
	scanner.Scan() // greeting
	io.WriteString(c, "EHLO localhost\r\n")
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "250 ") {
			break
		}
	}

	select {
	case ctx = <-ctxs:
	case <-time.After(5 * time.Second):
		t.Fatal("NewSession was not called")
	}
	return s, c, ctx
}

func TestServer_ConnContextCancelledOnDisconnect(t *testing.T) {
	s, c, ctx := testCtxServer(t)
	defer s.Close()

	if v, _ := ctx.Value(baseCtxKey{}).(string); v != "base" {
		t.Fatal("BaseContext value did not propagate to Conn.Context")
	}
	select {
	case <-ctx.Done():
		t.Fatal("Context cancelled while connection is still open")
	default:
	}

	c.Close()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Context not cancelled after client disconnect")
	}
}

func TestServer_ConnContextCancelledOnShutdown(t *testing.T) {
	s, c, ctx := testCtxServer(t)
	defer c.Close()

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- s.Shutdown(context.Background())
	}()

	// Shutdown must signal active connections through their context even
	// though it leaves the connections themselves open.
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Context not cancelled by Shutdown")
	}

	c.Close()
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatal("Shutdown error:", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return after connections closed")
	}
}

func TestServer_AuthRejectedDuringMailTransaction(t *testing.T) {
	_, s, c, scanner, _ := testServerEhlo(t)
	defer s.Close()
	defer c.Close()

	c.SetDeadline(time.Now().Add(10 * time.Second))

	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid MAIL response:", scanner.Text())
	}

	// RFC 4954 §4: AUTH is not permitted during a mail transaction (MUST reply 503).
	creds := base64.StdEncoding.EncodeToString([]byte("\x00username\x00password"))
	io.WriteString(c, "AUTH PLAIN "+creds+"\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "503 5.5.1 ") {
		t.Fatalf("Expected 503 5.5.1 for AUTH during mail transaction, got: %q", scanner.Text())
	}
}

func TestServer_AuthInvalidBase64Returns501(t *testing.T) {
	_, s, c, scanner, _ := testServerEhlo(t)
	defer s.Close()
	defer c.Close()

	c.SetDeadline(time.Now().Add(10 * time.Second))

	// RFC 4954 §4 / RFC 5321 §4.2.4: AUTH with no mechanism argument MUST be rejected with 501 5.5.4.
	io.WriteString(c, "AUTH\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "501 5.5.4 ") {
		t.Fatalf("Expected 501 5.5.4 for bare AUTH without mechanism, got: %q", scanner.Text())
	}

	// RFC 4954 §4: invalid base64 in initial response MUST be rejected with 501 5.5.2.
	io.WriteString(c, "AUTH PLAIN !!!not-base64!!!\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "501 5.5.2 ") {
		t.Fatalf("Expected 501 5.5.2 for invalid initial base64, got: %q", scanner.Text())
	}

	// Invalid base64 in challenge response MUST also be rejected with 501 5.5.2.
	io.WriteString(c, "AUTH PLAIN\r\n")
	scanner.Scan()
	if scanner.Text() != "334 " {
		t.Fatalf("Expected 334 challenge, got: %q", scanner.Text())
	}
	io.WriteString(c, "!!!not-base64!!!\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "501 5.5.2 ") {
		t.Fatalf("Expected 501 5.5.2 for invalid continuation base64, got: %q", scanner.Text())
	}

	// Extra arguments after initial response MUST be rejected with 501 5.5.4.
	io.WriteString(c, "AUTH PLAIN dGVzdA== extra\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "501 5.5.4 ") {
		t.Fatalf("Expected 501 5.5.4 for extra AUTH arguments, got: %q", scanner.Text())
	}
}

func TestServer_AuthBeforeStartTLSReturns538(t *testing.T) {
	_, s, c, scanner, _ := testServerEhlo(t, func(s *smtp.Server) {
		s.AllowInsecureAuth = false
	})
	defer s.Close()
	defer c.Close()

	c.SetDeadline(time.Now().Add(10 * time.Second))

	// RFC 4954 §6: AUTH over an unencrypted connection when encryption is required MUST reply 538 5.7.11.
	creds := base64.StdEncoding.EncodeToString([]byte("\x00username\x00password"))
	io.WriteString(c, "AUTH PLAIN "+creds+"\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "538 5.7.11 ") {
		t.Fatalf("Expected 538 5.7.11 for AUTH before STARTTLS, got: %q", scanner.Text())
	}
}

func TestServer_PostmasterForwardPathOnly(t *testing.T) {
	_, s, c, scanner, _ := testServerEhlo(t)
	defer s.Close()
	defer c.Close()

	c.SetDeadline(time.Now().Add(10 * time.Second))

	// RFC 5321 §4.1.1.3 allows domainless <Postmaster> only in RCPT TO, never in MAIL FROM or AUTH=.
	for _, cmd := range []string{
		"MAIL FROM:<Postmaster>",
		"MAIL FROM:<postmaster>",
		`MAIL FROM:<"postmaster">`,
		"MAIL FROM:postmaster",
		"MAIL FROM:<root@nsa.gov> AUTH=postmaster",
	} {
		io.WriteString(c, cmd+"\r\n")
		scanner.Scan()
		if !strings.HasPrefix(scanner.Text(), "501 ") {
			t.Fatalf("Expected 501 for %q, got: %q", cmd, scanner.Text())
		}
	}

	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatalf("Expected 250 for valid MAIL FROM, got: %q", scanner.Text())
	}

	// Bracketed domainless <Postmaster> (case-insensitive) is valid in RCPT TO.
	for _, cmd := range []string{
		"RCPT TO:<Postmaster>",
		"RCPT TO:<postmaster>",
	} {
		io.WriteString(c, cmd+"\r\n")
		scanner.Scan()
		if !strings.HasPrefix(scanner.Text(), "250 ") {
			t.Fatalf("Expected 250 for %q, got: %q", cmd, scanner.Text())
		}
	}

	// Quoted or unbracketed domainless postmaster is not a valid forward-path.
	for _, cmd := range []string{
		`RCPT TO:<"postmaster">`,
		"RCPT TO:postmaster",
	} {
		io.WriteString(c, cmd+"\r\n")
		scanner.Scan()
		if !strings.HasPrefix(scanner.Text(), "501 5.1.3 ") {
			t.Fatalf("Expected 501 5.1.3 for %q, got: %q", cmd, scanner.Text())
		}
	}
}

func TestServer_LocalPartRejectsControlCharsAndNUL(t *testing.T) {
	_, s, c, scanner, _ := testServerEhlo(t)
	defer s.Close()
	defer c.Close()

	c.SetDeadline(time.Now().Add(10 * time.Second))

	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatalf("Expected 250 for valid MAIL FROM, got: %q", scanner.Text())
	}

	// RFC 5321 §4.1.2 forbids control characters (0x00..0x1f and 0x7f) in both
	// dot-string and quoted-string local-parts; NUL must also return 501 5.1.3
	// without dropping the connection.
	for _, rcpt := range []string{
		"RCPT TO:<a\x01b@example.test>",
		"RCPT TO:<a\x00b@example.test>",
		"RCPT TO:<a\x7fb@example.test>",
		"RCPT TO:<\"a\x01b\"@example.test>",
		"RCPT TO:<\"a\x00b\"@example.test>",
		"RCPT TO:<\"a\x7fb\"@example.test>",
		"RCPT TO:<\"a\\\x01b\"@example.test>",
		"RCPT TO:<\"a\\\x00b\"@example.test>",
	} {
		io.WriteString(c, rcpt+"\r\n")
		if !scanner.Scan() {
			t.Fatalf("Connection dropped on %q (err=%v)", rcpt, scanner.Err())
		}
		if !strings.HasPrefix(scanner.Text(), "501 5.1.3 ") {
			t.Fatalf("Expected 501 5.1.3 for %q, got: %q", rcpt, scanner.Text())
		}
	}

	// Connection must remain usable after rejecting NUL/control-char paths.
	io.WriteString(c, "RCPT TO:<valid@example.test>\r\n")
	if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatalf("Expected 250 for subsequent valid RCPT TO, got: %q", scanner.Text())
	}
}

// Older Japanese carrier addresses (docomo, au/ezweb, SoftBank) still carry
// leading, trailing or consecutive dots in their local parts. They are not a
// valid RFC 5321 Dot-string, but Postfix accepts them and so must we on both
// MAIL FROM and RCPT TO (Open-Email/smtp-in#108), handing the backend the
// address exactly as the client sent it.
func TestServer_LegacyDottedLocalParts(t *testing.T) {
	be, s, c, scanner, _ := testServerEhlo(t)
	defer s.Close()
	defer c.Close()

	c.SetDeadline(time.Now().Add(10 * time.Second))

	// send reports a wrong reply without stopping, so one run shows every
	// refused form on both paths.
	send := func(cmd, wantPrefix string) bool {
		t.Helper()
		io.WriteString(c, cmd+"\r\n")
		if !scanner.Scan() {
			t.Fatalf("Connection dropped on %q (err=%v)", cmd, scanner.Err())
		}
		if !strings.HasPrefix(scanner.Text(), wantPrefix) {
			t.Errorf("Expected %q for %q, got: %q", wantPrefix, cmd, scanner.Text())
			return false
		}
		return true
	}
	deliver := func() *message {
		t.Helper()
		n := len(be.anonmsgs)
		if !send("DATA", "354 ") {
			t.FailNow()
		}
		io.WriteString(c, "Subject: hi\r\n\r\nbody\r\n")
		if !send(".", "250 ") || len(be.anonmsgs) != n+1 {
			t.FailNow()
		}
		return be.anonmsgs[n]
	}

	legacy := []string{
		"taro..yamada@docomo.ne.jp",
		"foo.@ezweb.ne.jp",
		".foo@example.com",
	}

	// RCPT TO: every legacy form is accepted and reaches the backend as sent.
	send("MAIL FROM:<normal.name@example.com>", "250 ")
	var accepted []string
	for _, addr := range append([]string{"normal.name@example.com"}, legacy...) {
		if send("RCPT TO:<"+addr+">", "250 ") {
			accepted = append(accepted, addr)
		}
	}
	msg := deliver()
	if fmt.Sprint(msg.To) != fmt.Sprint(accepted) {
		t.Errorf("RCPT TO reached the backend as %q, want %q", msg.To, accepted)
	}

	// MAIL FROM: the same, one transaction per form.
	for _, addr := range legacy {
		if !send("MAIL FROM:<"+addr+">", "250 ") {
			continue
		}
		send("RCPT TO:<normal.name@example.com>", "250 ")
		if msg := deliver(); msg.From != addr {
			t.Errorf("MAIL FROM:<%s> reached the backend as %q", addr, msg.From)
		}
	}

	// The AUTH= mailbox (RFC 4954 §5) shares the local-part parser.
	if send("MAIL FROM:<normal.name@example.com> AUTH=foo.@ezweb.ne.jp", "250 ") {
		if opts := be.sessions[0].msg.Opts; opts == nil || opts.Auth == nil || *opts.Auth != "foo.@ezweb.ne.jp" {
			t.Errorf("AUTH=foo.@ezweb.ne.jp reached the backend as %+v", opts)
		}
		send("RSET", "250 ")
	}
}

// Accepting legacy dots must not loosen any other MAIL FROM refusal: control
// characters, NUL, whitespace and the specials other than '.' still get 501,
// dotted or not, and the connection stays usable.
func TestServer_MailFromLocalPartRefusals(t *testing.T) {
	_, s, c, scanner, _ := testServerEhlo(t)
	defer s.Close()
	defer c.Close()

	c.SetDeadline(time.Now().Add(10 * time.Second))

	for _, cmd := range []string{
		"MAIL FROM:<a\x01b@example.test>",
		"MAIL FROM:<a\x00b@example.test>",
		"MAIL FROM:<a\x7fb@example.test>",
		"MAIL FROM:<taro..\x01yamada@docomo.ne.jp>",
		"MAIL FROM:<foo.\x00@ezweb.ne.jp>",
		"MAIL FROM:<.\x7ffoo@example.com>",
		"MAIL FROM:<\"a\x01b\"@example.test>",
		"MAIL FROM:<\"a\x00b\"@example.test>",
		"MAIL FROM:<a,b@example.test>",
		"MAIL FROM:<a;b@example.test>",
		"MAIL FROM:<a(b@example.test>",
		"MAIL FROM:<a[b@example.test>",
		"MAIL FROM:<a\\b@example.test>",
		"MAIL FROM:<a..b,c@example.test>",
	} {
		io.WriteString(c, cmd+"\r\n")
		if !scanner.Scan() {
			t.Fatalf("Connection dropped on %q (err=%v)", cmd, scanner.Err())
		}
		if !strings.HasPrefix(scanner.Text(), "501 ") {
			t.Fatalf("Expected 501 for %q, got: %q", cmd, scanner.Text())
		}
	}

	io.WriteString(c, "MAIL FROM:<valid@example.test>\r\n")
	if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatalf("Expected 250 for subsequent valid MAIL FROM, got: %q", scanner.Text())
	}
}
