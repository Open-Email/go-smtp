package smtp_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

func TestGreetingCallbacksCanCloseConnection(t *testing.T) {
	for _, location := range []string{"check", "constructor-reuse", "constructor-replace", "old-logout"} {
		t.Run(location, func(t *testing.T) {
			var calls atomic.Int32
			loggedOut := make(chan struct{}, 2)
			next := &closeObservedSession{loggedOut: loggedOut}
			oldSessions := make(chan *session, 1)
			_, srv, conn, scanner := testServerGreeted(t, func(s *smtp.Server) {
				be := s.Backend.(*backend)
				s.Backend = smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
					if calls.Add(1) > 1 {
						if location == "old-logout" {
							return next, nil
						}
						old := c.Session()
						c.Close()
						if location == "constructor-replace" {
							return next, nil
						}
						return old, nil
					}
					inner, err := be.NewSession(c)
					if err != nil {
						return nil, err
					}
					oldSessions <- inner.(*session)
					if location == "old-logout" {
						return &reusableGreetingSession{session: inner.(*session), conn: c,
							check:    func(context.Context, string) error { return nil },
							onLogout: func() { c.Close() },
						}, nil
					}
					if location == "check" {
						return &reusableGreetingSession{session: inner.(*session), conn: c, check: func(context.Context, string) error {
							c.Close()
							return net.ErrClosed
						}}, nil
					}
					return inner, nil
				})
			})
			defer srv.Close()
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			io.WriteString(conn, "EHLO original.example\r\n")
			readGreetingReply(t, scanner, "250")
			old := <-oldSessions
			io.WriteString(conn, "EHLO dropped.example\r\n")
			if scanner.Scan() {
				t.Fatalf("Close sent an unexpected response: %q", scanner.Text())
			}
			if err, ok := scanner.Err().(net.Error); ok && err.Timeout() {
				t.Fatal("greeting callback deadlocked instead of closing the connection")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				t.Fatal(err)
			}
			if old.getLogoutCount() != 1 {
				t.Fatalf("old session logged out %d times, want 1", old.getLogoutCount())
			}
			if (location == "constructor-replace" || location == "old-logout") && next.logouts.Load() != 1 {
				t.Fatal("Close leaked the uninstalled candidate")
			}
		})
	}
}

func TestFailedGreetingRestoresSessionDeadline(t *testing.T) {
	for _, originalLimit := range []bool{false, true} {
		t.Run(fmt.Sprintf("original-limit=%v", originalLimit), func(t *testing.T) {
			var calls atomic.Int32
			_, srv, conn, scanner := testServerGreeted(t, func(s *smtp.Server) {
				s.Backend = smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
					if calls.Add(1) == 1 {
						if originalLimit {
							c.SetSessionDeadline(time.Now().Add(300 * time.Millisecond))
						}
						return ctxSession{}, nil
					}
					if originalLimit {
						c.SetSessionDeadline(time.Time{}) // must not disable the old limit
					} else {
						c.SetSessionDeadline(time.Now().Add(-time.Second)) // must not expire the old session
					}
					return nil, errors.New("greeting allocation refused")
				})
			})
			defer srv.Close()
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			io.WriteString(conn, "EHLO original.example\r\n")
			readGreetingReply(t, scanner, "250")
			io.WriteString(conn, "EHLO refused.example\r\n")
			readGreetingReply(t, scanner, "451")
			io.WriteString(conn, "NOOP\r\n")
			readGreetingReply(t, scanner, "250")
			if originalLimit {
				readGreetingReply(t, scanner, "421")
			}
		})
	}
}

func TestGreetingPanicRestoresMetadataBeforeLogout(t *testing.T) {
	var calls atomic.Int32
	observed := make(chan string, 1)
	_, srv, conn, scanner := testServerGreeted(t, func(s *smtp.Server) {
		be := s.Backend.(*backend)
		s.ErrorLog = log.New(io.Discard, "", 0)
		s.Backend = smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
			if calls.Add(1) > 1 {
				c.SetSessionDeadline(time.Now().Add(-time.Second))
				panic("allocation failed")
			}
			inner, err := be.NewSession(c)
			if err != nil {
				return nil, err
			}
			return &reusableGreetingSession{session: inner.(*session), conn: c,
				check:    func(context.Context, string) error { return nil },
				onLogout: func() { observed <- c.Greeting() + "/" + c.Hostname() },
			}, nil
		})
	})
	defer srv.Close()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(conn, "HELO original.example\r\n")
	readGreetingReply(t, scanner, "250")
	io.WriteString(conn, "EHLO candidate.example\r\n")
	readGreetingReply(t, scanner, "421")
	select {
	case got := <-observed:
		if got != "HELO/original.example" {
			t.Fatalf("Logout saw failed proposal %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("panic did not clean up the old session")
	}
}

func TestGreetingReplacementOrdering(t *testing.T) {
	var calls atomic.Int32
	events := make(chan string, 2)
	loggedOut := make(chan struct{}, 1)
	next := &closeObservedSession{loggedOut: loggedOut}
	_, srv, conn, scanner := testServerGreeted(t, func(s *smtp.Server) {
		be := s.Backend.(*backend)
		s.Backend = smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
			if calls.Add(1) > 1 {
				if old := c.Session(); old == nil || old.(*reusableGreetingSession).getLogoutCount() != 0 {
					return nil, errors.New("constructor lost the live old session")
				}
				events <- "new session returned"
				return next, nil
			}
			inner, err := be.NewSession(c)
			if err != nil {
				return nil, err
			}
			return &reusableGreetingSession{session: inner.(*session), conn: c,
				check: func(context.Context, string) error { return nil },
				onLogout: func() {
					if c.Session() != next {
						events <- "candidate not installed before old Logout"
						return
					}
					events <- "old session logged out"
				},
			}, nil
		})
	})
	defer srv.Close()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(conn, "EHLO original.example\r\n")
	readGreetingReply(t, scanner, "250")
	io.WriteString(conn, "EHLO candidate.example\r\n")
	readGreetingReply(t, scanner, "250")
	if first, second := <-events, <-events; first != "new session returned" || second != "old session logged out" {
		t.Fatalf("unexpected replacement order: %q, %q", first, second)
	}
	if next.resets.Load() != 0 {
		t.Fatal("fresh replacement was reset as though it were a reused session")
	}
}

func TestAuthenticatedGreetingRetainsSessionAndChecksPolicy(t *testing.T) {
	for _, command := range []string{"HELO", "EHLO", "LHLO"} {
		t.Run(command, func(t *testing.T) {
			var calls atomic.Int32
			sessions := make(chan *greetingCheckSession, 1)
			_, srv, conn, scanner := testServer(t, func(s *smtp.Server) {
				s.LMTP = command == "LHLO"
				be := s.Backend.(*backend)
				s.Backend = smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
					calls.Add(1)
					inner, err := be.NewSession(c)
					if err != nil {
						return nil, err
					}
					sess := &greetingCheckSession{session: inner.(*session), conn: c}
					sessions <- sess
					return sess, nil
				})
			})
			defer srv.Close()
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			readGreetingReply(t, scanner, "220")
			send := func(command, code string) {
				t.Helper()
				io.WriteString(conn, command+"\r\n")
				readGreetingReply(t, scanner, code)
			}
			send(command+" original.example", "250")
			sess := <-sessions
			send("AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk", "235")
			send("MAIL FROM:<sender@example.com>", "250")
			send("RCPT TO:<recipient@example.com>", "250")
			send(command+" refused.example", "550")
			send("DATA", "354")
			io.WriteString(conn, "Subject: retained\r\n\r\nbody\r\n.\r\n")
			readGreetingReply(t, scanner, "250")
			send("MAIL FROM:<sender@example.com>", "250")
			send("RCPT TO:<recipient@example.com>", "250")
			send(command+" accepted.example", "250")
			if sess.conn.Session() != sess || calls.Load() != 1 || sess.getLogoutCount() != 0 {
				t.Fatal("authenticated re-greeting replaced the session")
			}
			if len(sess.getChecked()) != 2 || sess.conn.Hostname() != "accepted.example" || sess.conn.Greeting() != command {
				t.Fatal("authenticated re-greeting bypassed the policy or lost the new greeting")
			}
			send("DATA", "502") // accepted greeting cleared the previous envelope
			send("AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk", "503")
			send("MAIL FROM:<sender@example.com>", "250")
			send("RCPT TO:<recipient@example.com>", "250")
			send("DATA", "354")
			io.WriteString(conn, "Subject: still authenticated\r\n\r\nbody\r\n.\r\n")
			readGreetingReply(t, scanner, "250")
			send("NOOP", "250")
			sess.backend.mu.Lock()
			defer sess.backend.mu.Unlock()
			if len(sess.backend.messages) != 2 || len(sess.backend.anonmsgs) != 0 {
				t.Fatal("a repeated greeting lost the authenticated backend identity")
			}
		})
	}
}

type chunkGreetingSession struct {
	ctxSession
	checks atomic.Int32
	ended  chan error
}

func (s *chunkGreetingSession) CheckGreeting(context.Context, string) error {
	s.checks.Add(1)
	return nil
}

func (s *chunkGreetingSession) Data(_ context.Context, r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	s.ended <- err
	return err
}

func TestGreetingDuringBDATLeavesTransferIntact(t *testing.T) {
	for _, finish := range []bool{false, true} {
		t.Run(fmt.Sprintf("finish=%v", finish), func(t *testing.T) {
			var calls atomic.Int32
			sess := &chunkGreetingSession{ended: make(chan error, 1)}
			_, srv, conn, scanner := testServerGreeted(t, func(s *smtp.Server) {
				s.Backend = smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
					calls.Add(1)
					return sess, nil
				})
			})
			defer srv.Close()
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			send := func(command, code string) {
				t.Helper()
				io.WriteString(conn, command+"\r\n")
				readGreetingReply(t, scanner, code)
			}
			send("EHLO original.example", "250")
			send("MAIL FROM:<sender@example.com>", "250")
			send("RCPT TO:<recipient@example.com>", "250")
			io.WriteString(conn, "BDAT 1\r\nx")
			readGreetingReply(t, scanner, "250")
			send("EHLO candidate.example", "550")
			if sess.checks.Load() != 0 || calls.Load() != 1 {
				t.Fatal("greeting callback ran during an open BDAT transfer")
			}
			if finish {
				send("BDAT 0 LAST", "250")
			} else {
				send("RSET", "250")
			}
			select {
			case err := <-sess.ended:
				if finish && err != nil {
					t.Fatalf("refused greeting aborted the transfer: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("BDAT callback did not finish")
			}
			send("EHLO candidate.example", "250")
			if sess.checks.Load() != 1 || calls.Load() != 2 {
				t.Fatal("greeting callbacks did not resume after BDAT")
			}
		})
	}
}

// Session does not require a comparable dynamic type. Such values represent
// fresh sessions; checking for explicit reuse must not turn a greeting into 421.
type uncomparableGreetingSession struct {
	ctxSession
	state   []byte
	logouts *atomic.Int32
}

func (s uncomparableGreetingSession) Logout() error {
	s.logouts.Add(1)
	return nil
}

func TestGreetingAcceptsUncomparableSessionValues(t *testing.T) {
	var logouts atomic.Int32
	_, srv, conn, scanner := testServerGreeted(t, func(s *smtp.Server) {
		s.Backend = smtp.BackendFunc(func(*smtp.Conn) (smtp.Session, error) {
			return uncomparableGreetingSession{state: []byte{1}, logouts: &logouts}, nil
		})
	})
	defer srv.Close()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	for _, command := range []string{"EHLO original.example", "EHLO candidate.example"} {
		io.WriteString(conn, command+"\r\n")
		readGreetingReply(t, scanner, "250")
	}
	io.WriteString(conn, "QUIT\r\n")
	readGreetingReply(t, scanner, "221")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if logouts.Load() != 2 {
		t.Fatalf("fresh session values logged out %d times, want 2", logouts.Load())
	}
}
