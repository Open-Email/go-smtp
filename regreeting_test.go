package smtp_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

func TestNewSessionRefusalPreservesGreetingAndTransaction(t *testing.T) {
	for _, command := range []string{"HELO", "EHLO", "LHLO"} {
		for _, preflight := range []bool{false, true} {
			for _, transient := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/check=%v/transient=%v", command, preflight, transient), func(t *testing.T) {
					var calls atomic.Int32
					connections := make(chan *smtp.Conn, 1)
					oldSessions := make(chan *session, 1)
					proposed := make(chan string, 1)
					_, srv, conn, scanner := testServer(t, func(s *smtp.Server) {
						s.LMTP = command == "LHLO"
						be := s.Backend.(*backend)
						s.Backend = smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
							if calls.Add(1) > 1 {
								proposed <- c.Greeting() + "/" + c.Hostname()
								if transient {
									return nil, errors.New("session allocation failed")
								}
								return nil, &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Greeting refused"}
							}
							sess, err := be.NewSession(c)
							if err != nil {
								return nil, err
							}
							oldSessions <- sess.(*session)
							connections <- c
							if preflight {
								return &greetingCheckSession{session: sess.(*session), conn: c}, nil
							}
							return sess, nil
						})
					})
					defer srv.Close()
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					readGreetingReply(t, scanner, "220")
					send := func(cmd, code string) {
						t.Helper()
						io.WriteString(conn, cmd+"\r\n")
						readGreetingReply(t, scanner, code)
					}
					firstCommand := "HELO"
					if command == "LHLO" {
						firstCommand = "LHLO"
					}
					send(firstCommand+" original.example", "250")
					c, old := <-connections, <-oldSessions
					original := c.Session()
					// A refusal must preserve authentication as well as the envelope.
					send("AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk", "235")
					send("MAIL FROM:<sender@example.com>", "250")
					send("RCPT TO:<recipient@example.com>", "250")
					code := "550"
					if transient {
						code = "451"
					}
					send(command+" candidate.example", code)
					if got := <-proposed; got != command+"/candidate.example" {
						t.Fatalf("NewSession saw %q", got)
					}
					if c.Session() != original || c.Greeting() != firstCommand || c.Hostname() != "original.example" {
						t.Fatal("refusal changed the session or greeting")
					}
					if old.getLogoutCount() != 0 {
						t.Fatal("refusal logged out the old session")
					}
					send("AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk", "503")
					send("DATA", "354")
					io.WriteString(conn, "Subject: retained\r\n\r\nbody\r\n.\r\n")
					readGreetingReply(t, scanner, "250")
					send("QUIT", "221")
				})
			}
		}
	}
}

type reusableGreetingSession struct {
	*session
	conn     *smtp.Conn
	resets   atomic.Int32
	check    func(context.Context, string, string) error
	onLogout func()
}

func (s *reusableGreetingSession) Reset() {
	s.resets.Add(1)
	s.session.Reset()
}

func (s *reusableGreetingSession) ReGreeting(ctx context.Context, domain, command string) error {
	return s.check(ctx, domain, command)
}

func (s *reusableGreetingSession) Logout() error {
	if s.onLogout != nil {
		s.onLogout()
	}
	return s.session.Logout()
}

func (s *reusableGreetingSession) CheckGreeting(context.Context, string) error {
	return errors.New("CheckGreeting must not run when ReGreeting is implemented")
}

func TestReGreetingReusesSessionAndResetsOnlyOnSuccess(t *testing.T) {
	for _, command := range []string{"HELO", "EHLO", "LHLO"} {
		t.Run(command, func(t *testing.T) {
			var created atomic.Int32
			sessions := make(chan *reusableGreetingSession, 1)
			contexts := make(chan context.Context, 2)
			_, srv, conn, scanner := testServer(t, func(s *smtp.Server) {
				s.LMTP = command == "LHLO"
				be := s.Backend.(*backend)
				s.Backend = smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
					if created.Add(1) > 1 {
						return nil, errors.New("only one live session is allowed")
					}
					inner, err := be.NewSession(c)
					if err != nil {
						return nil, err
					}
					sess := &reusableGreetingSession{session: inner.(*session), conn: c}
					sess.check = func(ctx context.Context, domain, proposed string) error {
						contexts <- ctx
						if c.Hostname() != "original.example" || c.Greeting() != command || proposed != command {
							return errors.New("ReGreeting saw incorrect greeting metadata")
						}
						if domain == "refused.example" {
							return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Greeting refused"}
						}
						return nil
					}
					sessions <- sess
					return sess, nil
				})
			})
			defer srv.Close()
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			readGreetingReply(t, scanner, "220")
			send := func(cmd, code string) {
				t.Helper()
				io.WriteString(conn, cmd+"\r\n")
				readGreetingReply(t, scanner, code)
			}
			send(command+" original.example", "250")
			sess := <-sessions
			send("AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk", "235")
			send("MAIL FROM:<sender@example.com>", "250")
			send("RCPT TO:<recipient@example.com>", "250")
			send(command+" refused.example", "550")
			if sess.resets.Load() != 0 || sess.getLogoutCount() != 0 {
				t.Fatal("refusal reset or logged out the session")
			}
			ctx := <-contexts
			select {
			case <-ctx.Done():
			default:
				t.Fatal("ReGreeting context was not cancelled on return")
			}
			send("DATA", "354")
			io.WriteString(conn, "Subject: retained\r\n\r\nbody\r\n.\r\n")
			readGreetingReply(t, scanner, "250")
			// A following command synchronizes with handleData's deferred Reset.
			send("MAIL FROM:<sender@example.com>", "250")
			send("RCPT TO:<recipient@example.com>", "250")
			before := sess.resets.Load()
			send(command+" accepted.example", "250")
			if created.Load() != 1 || sess.conn.Session() != sess || sess.getLogoutCount() != 0 {
				t.Fatal("accepted re-greeting replaced the session")
			}
			if sess.resets.Load() != before+1 || sess.conn.Hostname() != "accepted.example" || sess.conn.Greeting() != command {
				t.Fatal("accepted re-greeting did not reset the transaction or update metadata")
			}
			send("DATA", "502")
			send("AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk", "503")
			send("QUIT", "221")
		})
	}
}

func TestServerCloseDuringNewSessionReplacement(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail=%v", fail), func(t *testing.T) {
			var created atomic.Int32
			entered, release := make(chan struct{}), make(chan struct{})
			loggedOut := make(chan struct{}, 2)
			first, next := &closeObservedSession{loggedOut: loggedOut}, &closeObservedSession{loggedOut: loggedOut}
			_, srv, conn, scanner := testServerGreeted(t, func(s *smtp.Server) {
				s.Backend = smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
					if created.Add(1) == 1 {
						return first, nil
					}
					close(entered)
					<-release
					if fail {
						return nil, errors.New("allocation failed during shutdown")
					}
					return next, nil
				})
			})
			defer srv.Close()
			defer conn.Close()
			defer close(release)
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			io.WriteString(conn, "EHLO original.example\r\n")
			readGreetingReply(t, scanner, "250")
			io.WriteString(conn, "EHLO candidate.example\r\n")
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("replacement did not start")
			}
			if err := srv.Close(); err != nil {
				t.Fatal(err)
			}
			<-loggedOut
			if first.logouts.Load() != 1 {
				t.Fatal("old session was not logged out exactly once")
			}
			// Release allocation after Close has taken the old session. The
			// serve loop must clean up a newly allocated session as well.
			release <- struct{}{}
			if !fail {
				select {
				case <-loggedOut:
				case <-time.After(5 * time.Second):
					t.Fatal("replacement session leaked after shutdown")
				}
				if next.logouts.Load() != 1 || first.logouts.Load() != 1 {
					t.Fatal("a session was logged out more than once")
				}
			}
		})
	}
}

type closeObservedSession struct {
	ctxSession
	logouts       atomic.Int32
	loggedOut     chan<- struct{}
	panicOnLogout bool
}

func (s *closeObservedSession) Logout() error {
	s.logouts.Add(1)
	s.loggedOut <- struct{}{}
	if s.panicOnLogout {
		panic("old session logout failed")
	}
	return nil
}

func TestReplacementSessionCleanedUpWhenOldLogoutPanics(t *testing.T) {
	var created atomic.Int32
	loggedOut := make(chan struct{}, 2)
	first := &closeObservedSession{loggedOut: loggedOut, panicOnLogout: true}
	next := &closeObservedSession{loggedOut: loggedOut}
	_, srv, conn, scanner := testServerGreeted(t, func(s *smtp.Server) {
		s.ErrorLog = log.New(io.Discard, "", 0)
		s.Backend = smtp.BackendFunc(func(*smtp.Conn) (smtp.Session, error) {
			if created.Add(1) == 1 {
				return first, nil
			}
			return next, nil
		})
	})
	defer srv.Close()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "EHLO original.example\r\n")
	readGreetingReply(t, scanner, "250")
	io.WriteString(conn, "EHLO candidate.example\r\n")
	readGreetingReply(t, scanner, "421")
	if first.logouts.Load() != 1 || next.logouts.Load() != 1 {
		t.Fatal("panic leaked or logged a session out twice")
	}
}

func TestServerCloseSerializesLogoutWithReGreeting(t *testing.T) {
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var inCallback atomic.Bool
	logoutDuringCallback := make(chan bool, 1)
	_, srv, conn, scanner := testServerGreeted(t, func(s *smtp.Server) {
		be := s.Backend.(*backend)
		s.Backend = smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
			inner, err := be.NewSession(c)
			if err != nil {
				return nil, err
			}
			sess := &reusableGreetingSession{session: inner.(*session), conn: c}
			sess.check = func(ctx context.Context, _, _ string) error {
				inCallback.Store(true)
				defer inCallback.Store(false)
				close(entered)
				<-ctx.Done()
				close(cancelled)
				<-release
				return ctx.Err()
			}
			sess.onLogout = func() { logoutDuringCallback <- inCallback.Load() }
			return sess, nil
		})
	})
	defer srv.Close()
	defer conn.Close()
	defer close(release)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	wait := func(ch <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatal(what)
		}
	}
	io.WriteString(conn, "EHLO original.example\r\n")
	readGreetingReply(t, scanner, "250")
	io.WriteString(conn, "EHLO candidate.example\r\n")
	wait(entered, "ReGreeting did not start")
	closed := make(chan struct{})
	go func() { defer close(closed); srv.Close() }()
	wait(cancelled, "shutdown did not cancel ReGreeting's context")
	release <- struct{}{}
	wait(closed, "shutdown did not finish")
	if <-logoutDuringCallback {
		t.Fatal("Logout ran concurrently with ReGreeting")
	}
}
