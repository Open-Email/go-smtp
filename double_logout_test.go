package smtp_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

// A session is logged out once. Re-EHLO, STARTTLS and XCLIENT replace the session by logging
// it out, and Conn.Close (Server.Close) logs out whatever session it finds. If a replacing
// command reads c.session, logs it out, and only then clears it, a Conn.Close that runs while
// it is inside Logout finds the same session and logs it out a second time (issue #17).

type blockingLogoutSession struct {
	logouts  atomic.Int32
	inLogout chan struct{} // closed when the first Logout starts
	release  chan struct{} // the first Logout returns once this is closed
}

func newBlockingLogoutSession() *blockingLogoutSession {
	return &blockingLogoutSession{inLogout: make(chan struct{}), release: make(chan struct{})}
}

func (s *blockingLogoutSession) Reset() {}

func (s *blockingLogoutSession) Logout() error {
	if s.logouts.Add(1) == 1 {
		close(s.inLogout)
		<-s.release
	}
	return nil
}

func (s *blockingLogoutSession) Mail(context.Context, string, *smtp.MailOptions) error { return nil }
func (s *blockingLogoutSession) Rcpt(context.Context, string, *smtp.RcptOptions) error { return nil }
func (s *blockingLogoutSession) Data(context.Context, io.Reader) error                 { return nil }

func TestSessionLoggedOutOnceWhenServerClosesDuringReplacement(t *testing.T) {
	for _, tc := range []struct {
		name string
		// replace sends the command that makes the server log the first session out.
		replace func(t *testing.T, c net.Conn, scanner *bufio.Scanner)
	}{
		{"re-EHLO", func(t *testing.T, c net.Conn, _ *bufio.Scanner) {
			io.WriteString(c, "EHLO localhost\r\n")
		}},
		{"STARTTLS", func(t *testing.T, c net.Conn, scanner *bufio.Scanner) {
			io.WriteString(c, "STARTTLS\r\n")
			if line := readResponseLine(t, scanner); !strings.HasPrefix(line, "220 ") {
				t.Fatalf("STARTTLS: %s", line)
			}
			// The server logs the session out after the handshake.
			go tls.Client(c, &tls.Config{InsecureSkipVerify: true}).Handshake()
		}},
		{"XCLIENT", func(t *testing.T, c net.Conn, _ *bufio.Scanner) {
			io.WriteString(c, "XCLIENT ADDR=192.0.2.1\r\n")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := newBlockingLogoutSession()
			var created atomic.Int32
			conns := make(chan *smtp.Conn, 1)
			srv := smtp.NewServer(smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
				if created.Add(1) == 1 {
					conns <- c
					return first, nil
				}
				// A session that replaces the first one (re-EHLO) is logged out by
				// Server.Close or by the connection's deferred Close; it must not block.
				next := newBlockingLogoutSession()
				close(next.release)
				return next, nil
			}))
			srv.Domain = "localhost"
			srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{generateTestCert()}}
			srv.EnableXCLIENT = true
			if err := srv.AddXCLIENTTrustedNetwork("127.0.0.0/8"); err != nil {
				t.Fatal(err)
			}

			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			go srv.Serve(l)
			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			scanner := bufio.NewScanner(c)
			readResponseLine(t, scanner) // greeting
			io.WriteString(c, "EHLO localhost\r\n")
			for {
				if line := readResponseLine(t, scanner); strings.HasPrefix(line, "250 ") {
					break
				}
			}
			conn := <-conns

			tc.replace(t, c, scanner)
			select {
			case <-first.inLogout:
			case <-time.After(5 * time.Second):
				t.Fatal("the server did not log the first session out")
			}

			// Close the server while that Logout runs, and let the Logout return only
			// once Conn.Close has run. If the replacing command left the session in
			// place, Conn.Close has run once it has taken it. If the command took the
			// session first, Conn.Close finds none and Server.Close returns.
			held := conn.Session() != nil
			closed := make(chan struct{})
			go func() { defer close(closed); srv.Close() }()
			if held {
				deadline := time.Now().Add(5 * time.Second)
				for conn.Session() != nil {
					if time.Now().After(deadline) {
						t.Fatal("Conn.Close did not take the session")
					}
					time.Sleep(time.Millisecond)
				}
			} else {
				select {
				case <-closed:
				case <-time.After(5 * time.Second):
					t.Fatal("Server.Close did not return")
				}
			}
			close(first.release)
			<-closed

			// Server.Close does not wait for the connection's goroutine; give a second
			// Logout time to land if it is coming.
			time.Sleep(100 * time.Millisecond)
			if n := first.logouts.Load(); n != 1 {
				t.Errorf("the first session was logged out %d times, want 1", n)
			}
		})
	}
}
