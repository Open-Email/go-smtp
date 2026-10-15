package smtp_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

func readGreetingReply(t *testing.T, scanner *bufio.Scanner, code string) {
	t.Helper()
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, code+"-") && !strings.HasPrefix(line, code+" ") {
			t.Fatalf("want %s response, got %q", code, line)
		}
		if strings.HasPrefix(line, code+" ") {
			return
		}
	}
	t.Fatalf("missing %s response: %v", code, scanner.Err())
}

func TestConnGreetingAvailableInNewSession(t *testing.T) {
	for _, lmtp := range []bool{false, true} {
		t.Run(fmt.Sprintf("lmtp=%v", lmtp), func(t *testing.T) {
			greetings := make(chan string, 4)
			_, server, conn, scanner := testServer(t, func(s *smtp.Server) {
				s.LMTP = lmtp
				s.Backend = smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
					greetings <- c.Greeting()
					return ctxSession{}, nil
				})
			})
			defer server.Close()
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			readGreetingReply(t, scanner, "220")
			commands := []string{"HELO", "EHLO", "HELO"}
			if lmtp {
				commands = []string{"LHLO", "LHLO"}
			}
			for _, command := range commands {
				io.WriteString(conn, command+" client.example\r\n")
				readGreetingReply(t, scanner, "250")
				select {
				case got := <-greetings:
					if got != command {
						t.Fatalf("NewSession greeting = %q, want %q", got, command)
					}
				case <-time.After(time.Second):
					t.Fatal("NewSession not called")
				}
			}
		})
	}
}

func TestConnGreetingClearedByStartTLS(t *testing.T) {
	connections := make(chan *smtp.Conn, 2)
	_, server, conn, scanner := testServer(t, func(s *smtp.Server) {
		s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{generateTestCert()}}
		s.Backend = smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
			connections <- c
			return ctxSession{}, nil
		})
	})
	defer server.Close()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	readGreetingReply(t, scanner, "220")
	io.WriteString(conn, "HELO client.example\r\n")
	readGreetingReply(t, scanner, "250")
	serverConn := <-connections
	if got := serverConn.Greeting(); got != "HELO" {
		t.Fatalf("got %q before STARTTLS", got)
	}
	io.WriteString(conn, "STARTTLS\r\n")
	readGreetingReply(t, scanner, "220")
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	scanner = bufio.NewScanner(tlsConn)
	// Wait for the server to finish resetting state after the handshake.
	io.WriteString(tlsConn, "NOOP\r\n")
	readGreetingReply(t, scanner, "250")
	if got := serverConn.Greeting(); got != "" {
		t.Fatalf("got %q after STARTTLS, want empty", got)
	}
	io.WriteString(tlsConn, "EHLO client.example\r\n")
	readGreetingReply(t, scanner, "250")
	serverConn = <-connections
	if got := serverConn.Greeting(); got != "EHLO" {
		t.Fatalf("got %q after TLS EHLO", got)
	}
}

// greetingCheckSession vets repeated greetings through smtp.GreetingSession.
type greetingCheckSession struct {
	*session
	conn *smtp.Conn

	mu      sync.Mutex
	checked []string // "domain while-current-greeting/while-current-hostname"
}

func (s *greetingCheckSession) CheckGreeting(ctx context.Context, domain string) error {
	s.mu.Lock()
	s.checked = append(s.checked, domain+" "+s.conn.Greeting()+"/"+s.conn.Hostname())
	s.mu.Unlock()
	switch domain {
	case "refused.example":
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Greeting refused"}
	case "broken.example":
		return errors.New("Greeting check failed")
	}
	return nil
}

func (s *greetingCheckSession) getChecked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.checked...)
}

// RFC 5321 section 4.1.4: after refusing an EHLO the server "MUST stay in the
// same state ... that it was in before the EHLO was received". A refused
// repeated greeting must therefore keep the current session, its greeting and
// the open mail transaction, instead of logging the session out first.
func TestServer_refusedReGreetingKeepsSession(t *testing.T) {
	var (
		mu       sync.Mutex
		sessions []*greetingCheckSession
	)
	_, s, c, scanner := testServerGreeted(t, func(s *smtp.Server) {
		be := s.Backend.(*backend)
		s.Backend = smtp.BackendFunc(func(conn *smtp.Conn) (smtp.Session, error) {
			inner, err := be.NewSession(conn)
			if err != nil {
				return nil, err
			}
			sess := &greetingCheckSession{session: inner.(*session), conn: conn}
			mu.Lock()
			sessions = append(sessions, sess)
			mu.Unlock()
			return sess, nil
		})
	})
	defer s.Close()
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	expect := func(command, want string) {
		t.Helper()
		io.WriteString(c, command+"\r\n")
		if !scanner.Scan() {
			t.Fatalf("%s: no reply: %v", command, scanner.Err())
		}
		line := scanner.Text()
		if !strings.HasPrefix(line, want) {
			t.Fatalf("%s: got %q, want prefix %q", command, line, want)
		}
		for strings.HasPrefix(line, want[:3]+"-") && scanner.Scan() {
			line = scanner.Text()
		}
	}
	countSessions := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(sessions)
	}
	sessionAt := func(i int) *greetingCheckSession {
		mu.Lock()
		defer mu.Unlock()
		return sessions[i]
	}

	expect("EHLO client.example", "250")
	expect("MAIL FROM:<root@nsa.gov>", "250 ")

	expect("HELO refused.example", "550 5.7.1 Greeting refused")
	expect("EHLO broken.example", "451 4.0.0 Greeting check failed")

	// The transaction opened under the first greeting is still in progress.
	expect("RCPT TO:<root@gchq.gov.uk>", "250 ")

	if n := countSessions(); n != 1 {
		t.Fatalf("refused greetings created sessions: got %d sessions, want 1", n)
	}
	first := sessionAt(0)
	if n := first.getLogoutCount(); n != 0 {
		t.Fatalf("refused greeting logged the session out %d times", n)
	}
	wantChecked := []string{
		"refused.example EHLO/client.example",
		"broken.example EHLO/client.example",
	}
	if got := first.getChecked(); strings.Join(got, ",") != strings.Join(wantChecked, ",") {
		t.Fatalf("CheckGreeting calls = %q, want %q", got, wantChecked)
	}
	if got := first.conn.Greeting(); got != "EHLO" {
		t.Fatalf("Conn.Greeting after refusals = %q, want EHLO", got)
	}

	// An accepted repeated greeting still replaces the session and resets
	// the transaction.
	expect("HELO accepted.example", "250 ")
	if n := countSessions(); n != 2 {
		t.Fatalf("accepted re-greeting: got %d sessions, want 2", n)
	}
	if n := first.getLogoutCount(); n != 1 {
		t.Fatalf("accepted re-greeting logged the old session out %d times, want 1", n)
	}
	if got := first.getChecked(); len(got) != 3 || got[2] != "accepted.example EHLO/client.example" {
		t.Fatalf("CheckGreeting calls = %q", got)
	}
	if got := sessionAt(1).getChecked(); len(got) != 0 {
		t.Fatalf("the new session was asked to check its own greeting: %q", got)
	}
	expect("MAIL FROM:<root@nsa.gov>", "250 ")
}
