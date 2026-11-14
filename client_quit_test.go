package smtp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// scriptedConn replays a fixed server script, records what the client wrote
// and whether it closed the connection.
type scriptedConn struct {
	faker
	written *bytes.Buffer
	flush   func() error
	closed  bool
}

func newScriptedConn(server string) *scriptedConn {
	server = strings.Join(strings.Split(server, "\n"), "\r\n")
	var written bytes.Buffer
	w := bufio.NewWriter(&written)
	c := &scriptedConn{written: &written, flush: w.Flush}
	c.ReadWriter = bufio.NewReadWriter(bufio.NewReader(strings.NewReader(server)), w)
	return c
}

func (c *scriptedConn) Close() error {
	c.closed = true
	return nil
}

func (c *scriptedConn) commands() string {
	c.flush()
	return strings.ReplaceAll(c.written.String(), "\r\n", "\n")
}

func TestQuitAfterResetSendsNoEHLO(t *testing.T) {
	conn := newScriptedConn("220 hello\n" +
		"250 mx at your service\n" + // EHLO
		"250 reset\n" + // RSET
		"221 bye\n")
	c := NewClient(conn)
	if err := c.Hello("r5.out.example"); err != nil {
		t.Fatalf("Hello: %v", err)
	}
	if err := c.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if err := c.Quit(); err != nil {
		t.Fatalf("Quit: %v", err)
	}
	if got, want := conn.commands(), "EHLO r5.out.example\nRSET\nQUIT\n"; got != want {
		t.Errorf("client wrote:\n%s\nwant:\n%s", got, want)
	}
	if !conn.closed {
		t.Error("Quit left the connection open")
	}
}

func TestResetKeepsSessionGreeted(t *testing.T) {
	conn := newScriptedConn("220 hello\n" +
		"250 mx at your service\n" + // EHLO
		"250 reset\n" + // RSET
		"250 ok\n" + // NOOP
		"250 sender ok\n") // MAIL
	c := NewClient(conn)
	if err := c.Hello("r5.out.example"); err != nil {
		t.Fatalf("Hello: %v", err)
	}
	if err := c.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if err := c.Hello("other.example"); err == nil {
		t.Error("Hello after Reset was accepted; want it refused like after any other command")
	}
	if err := c.Noop(); err != nil {
		t.Fatalf("Noop: %v", err)
	}
	if err := c.Mail("a@example.com", nil); err != nil {
		t.Fatalf("Mail: %v", err)
	}
	want := "EHLO r5.out.example\nRSET\nNOOP\nMAIL FROM:<a@example.com>\n"
	if got := conn.commands(); got != want {
		t.Errorf("client wrote:\n%s\nwant:\n%s", got, want)
	}
}

func TestQuitClosesWhenRefused(t *testing.T) {
	conn := newScriptedConn("220 hello\n" +
		"250 mx at your service\n" + // EHLO
		"500 what?\n") // QUIT
	c := NewClient(conn)
	if err := c.Hello("r5.out.example"); err != nil {
		t.Fatalf("Hello: %v", err)
	}
	err := c.Quit()
	var smtpErr *SMTPError
	if !errors.As(err, &smtpErr) || smtpErr.Code != 500 {
		t.Errorf("Quit error = %v, want the 500 reply", err)
	}
	if !conn.closed {
		t.Error("Quit left the connection open after a refused QUIT")
	}
}

func TestQuitTimeoutBoundsTheWait(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	go func() {
		r := bufio.NewReader(serverSide)
		serverSide.Write([]byte("220 hello\r\n"))
		r.ReadString('\n') // EHLO
		serverSide.Write([]byte("250 mx at your service\r\n"))
		r.ReadString('\n') // QUIT, never answered
		r.ReadString('\n') // returns once the client closes
	}()

	c := NewClient(clientSide)
	c.CommandTimeout = time.Minute
	c.QuitTimeout = 50 * time.Millisecond
	if err := c.Hello("r5.out.example"); err != nil {
		t.Fatalf("Hello: %v", err)
	}
	start := time.Now()
	if err := c.Quit(); err == nil {
		t.Error("Quit returned nil for a QUIT that was never answered")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Quit waited %v; QuitTimeout is 50ms", elapsed)
	}
	if _, err := clientSide.Write([]byte("x")); err == nil {
		t.Error("connection still writable after Quit timed out")
	}
}

func TestQuitBeforeGreeting(t *testing.T) {
	for name, tc := range map[string]struct {
		server, want string
		wantErr      bool
	}{
		"220 greeting":    {"220 hello\n221 bye\n", "QUIT\n", false},
		"554 greeting":    {"554 5.7.1 your IP is listed\n221 bye\n", "QUIT\n", false},
		"421 greeting":    {"421 shutting down\n", "", true},
		"broken greeting": {"hello?\n", "", true},
	} {
		t.Run(name, func(t *testing.T) {
			conn := newScriptedConn(tc.server)
			c := NewClient(conn)
			if err := c.Quit(); (err != nil) != tc.wantErr {
				t.Errorf("Quit = %v; want error: %v", err, tc.wantErr)
			}
			if got := conn.commands(); got != tc.want {
				t.Errorf("client wrote %q; want %q", got, tc.want)
			}
			if !conn.closed {
				t.Error("Quit left the connection open")
			}
		})
	}
}

func TestQuitTimeoutIncludesUnreadGreeting(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	c := NewClient(clientSide)
	c.CommandTimeout = time.Minute
	c.QuitTimeout = 40 * time.Millisecond
	start := time.Now()
	if err := c.Quit(); err == nil {
		t.Error("Quit returned nil without receiving a greeting")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Quit waited %v for the greeting; QuitTimeout is %v", elapsed, c.QuitTimeout)
	}
	serverSide.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := serverSide.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("peer Read = %v; want EOF after Quit closed the connection", err)
	}
}

func TestQuitTimeoutIncludesGreetingAndReply(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	serverDone := make(chan error, 1)
	go func() {
		// Most of the budget expires before the greeting arrives. A separate
		// full timeout for the QUIT reply would take roughly 700ms overall.
		timer := time.NewTimer(300 * time.Millisecond)
		defer timer.Stop()
		<-timer.C
		if _, err := serverSide.Write([]byte("220 hello\r\n")); err != nil {
			serverDone <- err
			return
		}
		r := bufio.NewReader(serverSide)
		line, err := r.ReadString('\n')
		if err != nil {
			serverDone <- err
			return
		}
		if line != "QUIT\r\n" {
			serverDone <- errors.New("expected QUIT without EHLO")
			return
		}
		_, err = r.ReadString('\n')
		if !errors.Is(err, io.EOF) {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()
	c := NewClient(clientSide)
	c.CommandTimeout = time.Minute
	c.QuitTimeout = 400 * time.Millisecond
	start := time.Now()
	if err := c.Quit(); err == nil {
		t.Error("Quit returned nil without receiving its reply")
	}
	if elapsed := time.Since(start); elapsed > 600*time.Millisecond {
		t.Errorf("Quit used separate greeting and reply budgets: waited %v; QuitTimeout is %v", elapsed, c.QuitTimeout)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server script: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not observe the client close after its QUIT timed out")
	}
}

func TestQuitAfterHello421WritesNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		server, want string
	}{
		"EHLO": {
			server: "220 hello\n421 4.3.2 service shutting down\n",
			want:   "EHLO sender.example\n",
		},
		"HELO fallback": {
			server: "220 hello\n500 EHLO unsupported\n421 4.3.2 service shutting down\n",
			want:   "EHLO sender.example\nHELO sender.example\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			conn := newScriptedConn(tc.server)
			c := NewClient(conn)
			err := c.Hello("sender.example")
			var smtpErr *SMTPError
			if !errors.As(err, &smtpErr) || smtpErr.Code != 421 {
				t.Fatalf("Hello = %v; want the 421 reply", err)
			}
			if err := c.Quit(); err != nil {
				t.Errorf("Quit after 421 = %v; want nil", err)
			}
			if got := conn.commands(); got != tc.want {
				t.Errorf("client wrote %q after 421; want %q", got, tc.want)
			}
			if !conn.closed {
				t.Error("Quit left the connection open after 421")
			}
		})
	}
}

func TestQuitAfterMail421WritesNothing(t *testing.T) {
	conn := newScriptedConn("220 hello\n250 hello\n421 4.3.2 service shutting down\n")
	c := NewClient(conn)
	err := c.Mail("sender@example.com", nil)
	var smtpErr *SMTPError
	if !errors.As(err, &smtpErr) || smtpErr.Code != 421 {
		t.Fatalf("Mail = %v; want the 421 reply", err)
	}
	if err := c.Quit(); err != nil {
		t.Errorf("Quit after 421 = %v; want nil", err)
	}
	if got, want := conn.commands(), "EHLO localhost\nMAIL FROM:<sender@example.com>\n"; got != want {
		t.Errorf("client wrote %q after 421; want %q", got, want)
	}
	if !conn.closed {
		t.Error("Quit left the connection open after 421")
	}
}

func TestQuitTimeoutIncludesTLSClose(t *testing.T) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatal(err)
	}
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	// The server stops reading after QUIT, so a TLS close_notify cannot be
	// written unless Quit closes the underlying transport when its budget ends.
	checkClosed := make(chan struct{})
	defer close(checkClosed)
	serverDone := make(chan error, 1)
	go func() {
		s := tls.Server(serverSide, &tls.Config{Certificates: []tls.Certificate{cert}})
		r := bufio.NewReader(s)
		if _, err := s.Write([]byte("220 hello\r\n")); err != nil {
			serverDone <- err
			return
		}
		if _, err := r.ReadString('\n'); err != nil {
			serverDone <- err
			return
		}
		if _, err := s.Write([]byte("250 hello\r\n")); err != nil {
			serverDone <- err
			return
		}
		line, err := r.ReadString('\n')
		if err != nil {
			serverDone <- err
			return
		}
		if line != "QUIT\r\n" {
			serverDone <- errors.New("expected QUIT")
			return
		}
		serverDone <- nil
		<-checkClosed
	}()
	c := NewClient(tls.Client(clientSide, &tls.Config{InsecureSkipVerify: true}))
	c.CommandTimeout = time.Second
	c.QuitTimeout = 40 * time.Millisecond
	if err := c.Hello("sender.example"); err != nil {
		t.Fatalf("Hello: %v", err)
	}
	start := time.Now()
	if err := c.Quit(); err == nil {
		t.Error("Quit returned nil without receiving its reply")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Quit waited %v including TLS teardown; QuitTimeout is %v", elapsed, c.QuitTimeout)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server script: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server never received QUIT")
	}
	serverSide.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := serverSide.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("peer Read = %v; want EOF after Quit closed the transport", err)
	}
}

func TestQuitAfterGreetingBeforeHello(t *testing.T) {
	conn := newScriptedConn("220 hello\n" + "221 bye\n")
	c := NewClient(conn)
	if err := c.greet(); err != nil {
		t.Fatalf("greet: %v", err)
	}
	if err := c.Quit(); err != nil {
		t.Fatalf("Quit: %v", err)
	}
	if got, want := conn.commands(), "QUIT\n"; got != want {
		t.Errorf("client wrote:\n%s\nwant:\n%s", got, want)
	}
}

func TestQuitAfterRefusedGreeting(t *testing.T) {
	conn := newScriptedConn("554 5.7.1 your IP is listed\n" + "221 bye\n")
	c := NewClient(conn)
	err := c.Hello("r5.out.example")
	var smtpErr *SMTPError
	if !errors.As(err, &smtpErr) || smtpErr.Code != 554 {
		t.Fatalf("Hello error = %v, want the 554 greeting", err)
	}
	if conn.closed {
		t.Fatal("a 554 greeting closed the connection before QUIT")
	}
	if err := c.Quit(); err != nil {
		t.Fatalf("Quit: %v", err)
	}
	if got, want := conn.commands(), "QUIT\n"; got != want {
		t.Errorf("client wrote:\n%s\nwant:\n%s", got, want)
	}
	if !conn.closed {
		t.Error("Quit left the connection open")
	}
}

func TestQuitAfterClosingGreeting(t *testing.T) {
	for name, server := range map[string]string{
		"421 greeting":   "421 shutting down\n",
		"no greeting":    "",
		"broken message": "hello?\n",
	} {
		t.Run(name, func(t *testing.T) {
			conn := newScriptedConn(server)
			c := NewClient(conn)
			if err := c.Hello("r5.out.example"); err == nil {
				t.Fatal("Hello succeeded without a 220 greeting")
			}
			if err := c.Quit(); err != nil {
				t.Errorf("Quit after failed greeting = %v; want nil", err)
			}
			if got := conn.commands(); got != "" {
				t.Errorf("client wrote %q after the greeting failed; want nothing", got)
			}
			if !conn.closed {
				t.Error("connection left open")
			}
		})
	}

	// Real transports return net.ErrClosed when greet already closed the
	// connection and Quit closes it again.
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	go func() {
		serverSide.Write([]byte("421 shutting down\r\n"))
		serverSide.Close()
	}()
	c := NewClient(clientSide)
	if err := c.Hello("r5.out.example"); err == nil {
		t.Fatal("Hello succeeded after 421 greeting")
	}
	if err := c.Quit(); err != nil {
		t.Errorf("Quit on real pipe after 421 greeting = %v; want nil", err)
	}
}

func TestQuitAfterBrokenStreamWritesNothing(t *testing.T) {
	t.Run("command timeout", func(t *testing.T) {
		clientSide, serverSide := net.Pipe()
		defer clientSide.Close()
		defer serverSide.Close()
		var commands []string
		serverDone := make(chan struct{})
		go func() {
			defer close(serverDone)
			r := bufio.NewReader(serverSide)
			serverSide.Write([]byte("220 hello\r\n"))
			if line, err := r.ReadString('\n'); err == nil {
				commands = append(commands, line)
				serverSide.Write([]byte("250 hello\r\n"))
			}
			// Read MAIL FROM and never answer it; read until client closes.
			for {
				line, err := r.ReadString('\n')
				if line != "" {
					commands = append(commands, line)
				}
				if err != nil {
					return
				}
			}
		}()

		c := NewClient(clientSide)
		c.CommandTimeout = 40 * time.Millisecond
		c.QuitTimeout = 500 * time.Millisecond
		if err := c.Hello("sender.example"); err != nil {
			t.Fatalf("Hello: %v", err)
		}
		if err := c.Mail("sender@example.com", nil); err == nil {
			t.Fatal("Mail succeeded without a reply")
		}
		start := time.Now()
		if err := c.Quit(); err != nil {
			t.Errorf("Quit after command timeout = %v; want nil", err)
		}
		if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
			t.Errorf("Quit waited %v after command timeout; want immediate close", elapsed)
		}
		<-serverDone
		if got, want := strings.Join(commands, ""), "EHLO sender.example\r\nMAIL FROM:<sender@example.com>\r\n"; got != want {
			t.Errorf("client wrote %q; want %q without QUIT", got, want)
		}
	})

	t.Run("protocol error", func(t *testing.T) {
		conn := newScriptedConn("220 hello\nnot an smtp reply\n221 bye\n")
		c := NewClient(conn)
		if err := c.Hello("sender.example"); err == nil {
			t.Fatal("Hello succeeded on malformed reply")
		}
		if err := c.Quit(); err != nil {
			t.Errorf("Quit after protocol error = %v; want nil", err)
		}
		if got, want := conn.commands(), "EHLO sender.example\n"; got != want {
			t.Errorf("client wrote %q; want %q", got, want)
		}
		if !conn.closed {
			t.Error("Quit left the connection open")
		}
	})

	t.Run("unclosed DATA", func(t *testing.T) {
		conn := newScriptedConn("220 hello\n250 hello\n250 sender ok\n250 rcpt ok\n354 go ahead\n")
		c := NewClient(conn)
		if err := c.Hello("sender.example"); err != nil {
			t.Fatalf("Hello: %v", err)
		}
		if err := c.Mail("sender@example.com", nil); err != nil {
			t.Fatalf("Mail: %v", err)
		}
		if err := c.Rcpt("rcpt@example.com", nil); err != nil {
			t.Fatalf("Rcpt: %v", err)
		}
		if _, err := c.Data(); err != nil {
			t.Fatalf("Data: %v", err)
		}
		if err := c.Quit(); err != nil {
			t.Errorf("Quit during open DATA = %v; want nil", err)
		}
		want := "EHLO sender.example\nMAIL FROM:<sender@example.com>\nRCPT TO:<rcpt@example.com>\nDATA\n"
		if got := conn.commands(); got != want {
			t.Errorf("client wrote %q during open DATA; want %q", got, want)
		}
		if !conn.closed {
			t.Error("Quit left the connection open")
		}
	})

	t.Run("closed DATA refused with 554 still sends QUIT", func(t *testing.T) {
		conn := newScriptedConn("220 hello\n250 hello\n250 sender ok\n250 rcpt ok\n354 go ahead\n554 message rejected\n221 bye\n")
		c := NewClient(conn)
		if err := c.Hello("sender.example"); err != nil {
			t.Fatalf("Hello: %v", err)
		}
		if err := c.Mail("sender@example.com", nil); err != nil {
			t.Fatalf("Mail: %v", err)
		}
		if err := c.Rcpt("rcpt@example.com", nil); err != nil {
			t.Fatalf("Rcpt: %v", err)
		}
		w, err := c.Data()
		if err != nil {
			t.Fatalf("Data: %v", err)
		}
		if _, err := io.WriteString(w, "Subject: test\r\n\r\nhi\r\n"); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.Close(); err == nil {
			t.Fatal("w.Close succeeded despite 554")
		}
		if err := c.Quit(); err != nil {
			t.Errorf("Quit after 554 DATA reply = %v; want nil", err)
		}
		want := "EHLO sender.example\nMAIL FROM:<sender@example.com>\nRCPT TO:<rcpt@example.com>\nDATA\nSubject: test\n\nhi\n.\nQUIT\n"
		if got := conn.commands(); got != want {
			t.Errorf("client wrote %q; want %q", got, want)
		}
		if !conn.closed {
			t.Error("Quit left the connection open")
		}
	})
}

func TestStartTLSSetupFailureEndsWithQuit(t *testing.T) {
	for name, tc := range map[string]struct {
		server, want string
	}{
		"STARTTLS not offered": {
			server: "220 hello\n" + "250 mx at your service\n" + "221 bye\n",
			want:   "EHLO r5.out.example\nQUIT\n",
		},
		"STARTTLS refused": {
			server: "220 hello\n" + "250-mx at your service\n" + "250 STARTTLS\n" + "454 TLS not available\n" + "221 bye\n",
			want:   "EHLO r5.out.example\nSTARTTLS\nQUIT\n",
		},
		"STARTTLS answered with 421": {
			server: "220 hello\n" + "250-mx at your service\n" + "250 STARTTLS\n" + "421 closing\n",
			want:   "EHLO r5.out.example\nSTARTTLS\n",
		},
		"EHLO refused": {
			server: "220 hello\n" + "550 access denied\n" + "221 bye\n",
			want:   "EHLO r5.out.example\nQUIT\n",
		},
		"EHLO answered with 421": {
			server: "220 hello\n" + "421 closing\n",
			want:   "EHLO r5.out.example\n",
		},
		"554 greeting": {
			server: "554 5.7.1 your IP is listed\n" + "221 bye\n",
			want:   "QUIT\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			conn := newScriptedConn(tc.server)
			c, err := NewClientStartTLSWithName(conn, nil, "r5.out.example")
			if err == nil || c != nil {
				t.Fatalf("NewClientStartTLSWithName = %v, %v; want a setup error", c, err)
			}
			if got := conn.commands(); got != tc.want {
				t.Errorf("client wrote:\n%s\nwant:\n%s", got, tc.want)
			}
			if !conn.closed {
				t.Error("connection left open after the setup failed")
			}
		})
	}
	if _, err := NewClientStartTLSWithName(newScriptedConn("220 hello\n250 mx\n221 bye\n"), nil, "h"); !errors.Is(err, ErrSTARTTLSUnsupported) {
		t.Errorf("error for a server without STARTTLS = %v, want ErrSTARTTLSUnsupported", err)
	}
}

func TestStartTLSSetupFailureBoundsIgnoredQuit(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	quitSeen := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		r := bufio.NewReader(serverSide)
		if _, err := io.WriteString(serverSide, "220 hello\r\n"); err != nil {
			serverDone <- err
			return
		}
		if line, err := r.ReadString('\n'); err != nil || line != "EHLO r5.out.example\r\n" {
			serverDone <- err
			return
		}
		if _, err := io.WriteString(serverSide, "250 mx at your service\r\n"); err != nil {
			serverDone <- err
			return
		}
		line, err := r.ReadString('\n')
		if err != nil || line != "QUIT\r\n" {
			serverDone <- errors.New("expected cleanup QUIT")
			return
		}
		close(quitSeen)
		// Ignore QUIT until the constructor's bounded cleanup closes the pipe.
		_, err = io.Copy(io.Discard, r)
		serverDone <- err
	}()

	start := time.Now()
	c, err := NewClientStartTLSWithName(clientSide, nil, "r5.out.example")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrSTARTTLSUnsupported) || c != nil {
		t.Fatalf("NewClientStartTLSWithName = %v, %v; want nil, ErrSTARTTLSUnsupported", c, err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("NewClientStartTLSWithName waited %v on ignored cleanup QUIT; want bounded well below 10s QuitTimeout", elapsed)
	}
	select {
	case <-quitSeen:
	default:
		t.Fatal("server never received cleanup QUIT")
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server script: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("NewClientStartTLSWithName returned without closing the transport")
	}
}

func TestQuitAfter421OrTimeoutOverTLS(t *testing.T) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, wrapped := range []bool{false, true} {
		namePrefix := "direct"
		if wrapped {
			namePrefix = "wrapped"
		}

		t.Run(namePrefix+"/421 closed by peer", func(t *testing.T) {
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			serverDone := make(chan error, 1)
			go func() {
				s := tls.Server(serverSide, &tls.Config{Certificates: []tls.Certificate{cert}})
				r := bufio.NewReader(s)
				if _, err := io.WriteString(s, "220 hello\r\n"); err != nil {
					serverDone <- err
					return
				}
				if _, err := r.ReadString('\n'); err != nil {
					serverDone <- err
					return
				}
				if _, err := io.WriteString(s, "250 hello\r\n"); err != nil {
					serverDone <- err
					return
				}
				if _, err := r.ReadString('\n'); err != nil {
					serverDone <- err
					return
				}
				if _, err := io.WriteString(s, "421 4.3.2 service shutting down\r\n"); err != nil {
					serverDone <- err
					return
				}
				_ = serverSide.Close()
				serverDone <- nil
			}()

			var conn net.Conn = tls.Client(clientSide, &tls.Config{InsecureSkipVerify: true})
			if wrapped {
				conn = &quitTLSDecorator{Conn: conn}
			}
			c := NewClient(conn)
			if err := c.Hello("sender.example"); err != nil {
				t.Fatalf("Hello: %v", err)
			}
			err := c.Mail("sender@example.com", nil)
			var smtpErr *SMTPError
			if !errors.As(err, &smtpErr) || smtpErr.Code != 421 {
				t.Fatalf("Mail = %v; want 421", err)
			}
			if err := <-serverDone; err != nil {
				t.Fatalf("server script: %v", err)
			}
			if err := c.Quit(); err != nil {
				t.Errorf("Quit after TLS 421 = %v; want nil", err)
			}
		})

		t.Run(namePrefix+"/command timeout with stalled peer", func(t *testing.T) {
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			release := make(chan struct{})
			defer close(release)
			mailSeen := make(chan error, 1)
			go func() {
				s := tls.Server(serverSide, &tls.Config{Certificates: []tls.Certificate{cert}})
				r := bufio.NewReader(s)
				if _, err := io.WriteString(s, "220 hello\r\n"); err != nil {
					mailSeen <- err
					return
				}
				if _, err := r.ReadString('\n'); err != nil {
					mailSeen <- err
					return
				}
				if _, err := io.WriteString(s, "250 hello\r\n"); err != nil {
					mailSeen <- err
					return
				}
				if _, err := r.ReadString('\n'); err != nil {
					mailSeen <- err
					return
				}
				mailSeen <- nil
				<-release
			}()

			var conn net.Conn = tls.Client(clientSide, &tls.Config{InsecureSkipVerify: true})
			if wrapped {
				conn = &quitTLSDecorator{Conn: conn}
			}
			c := NewClient(conn)
			c.CommandTimeout = 40 * time.Millisecond
			c.QuitTimeout = 2 * time.Second
			if err := c.Hello("sender.example"); err != nil {
				t.Fatalf("Hello: %v", err)
			}
			if err := c.Mail("sender@example.com", nil); err == nil {
				t.Fatal("Mail succeeded without a reply")
			}
			if err := <-mailSeen; err != nil {
				t.Fatalf("server script: %v", err)
			}
			start := time.Now()
			if err := c.Quit(); err != nil {
				t.Errorf("Quit after TLS command timeout = %v; want nil", err)
			}
			if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
				t.Errorf("Quit waited %v after TLS command timeout; want immediate abort", elapsed)
			}
			serverSide.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := serverSide.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Errorf("peer Read = %v; want EOF after Quit closed the transport", err)
			}
		})
	}
}

func TestQuitFollowsLoweredCommandTimeout(t *testing.T) {
	if got := NewClient(newScriptedConn("")).quitTimeout(); got != 10*time.Second {
		t.Fatalf("default quitTimeout = %v; want 10s", got)
	}
	cExplicit := NewClient(newScriptedConn(""))
	cExplicit.CommandTimeout = 40 * time.Millisecond
	cExplicit.QuitTimeout = 200 * time.Millisecond
	if got := cExplicit.quitTimeout(); got != 200*time.Millisecond {
		t.Fatalf("explicit quitTimeout = %v; want 200ms", got)
	}

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	go func() {
		r := bufio.NewReader(serverSide)
		_, _ = io.WriteString(serverSide, "220 hello\r\n")
		_, _ = r.ReadString('\n') // EHLO
		_, _ = io.WriteString(serverSide, "250 mx at your service\r\n")
		_, _ = io.Copy(io.Discard, r) // never answers QUIT
	}()

	c := NewClient(clientSide)
	c.CommandTimeout = 50 * time.Millisecond
	if err := c.Hello("r5.out.example"); err != nil {
		t.Fatalf("Hello: %v", err)
	}
	start := time.Now()
	if err := c.Quit(); err == nil {
		t.Error("Quit returned nil for an unanswered QUIT")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Quit waited %v when CommandTimeout was lowered to %v", elapsed, c.CommandTimeout)
	}
	serverSide.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := serverSide.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("peer Read = %v; want EOF after Quit timed out", err)
	}
}
