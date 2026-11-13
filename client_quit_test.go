package smtp

import (
	"bufio"
	"bytes"
	"errors"
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
	conn := newScriptedConn("220 hello\n" + "221 bye\n")
	c := NewClient(conn)
	if err := c.Quit(); err != nil {
		t.Fatalf("Quit: %v", err)
	}
	if got := conn.commands(); got != "" {
		t.Errorf("client wrote %q before reading the greeting; want nothing", got)
	}
	if !conn.closed {
		t.Error("Quit left the connection open")
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
			c.Quit()
			if got := conn.commands(); got != "" {
				t.Errorf("client wrote %q after the greeting failed; want nothing", got)
			}
			if !conn.closed {
				t.Error("connection left open")
			}
		})
	}
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
