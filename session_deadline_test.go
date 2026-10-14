package smtp_test

import (
	"bufio"
	"crypto/tls"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

func TestSessionDeadlineClosesOnEveryCommand(t *testing.T) {
	for _, command := range []string{"NOOP", "VRFY user@example.org", "RSET", "EHLO again.example.org", "nonsense", ""} {
		t.Run(command, func(t *testing.T) {
			connections := make(chan *smtp.Conn, 1)
			_, server, conn, scanner := testServer(t, func(s *smtp.Server) {
				s.ReadTimeout = time.Minute
				s.Backend = smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
					connections <- c
					return ctxSession{}, nil
				})
			})
			defer server.Close()
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			readGreetingReply(t, scanner, "220")
			io.WriteString(conn, "EHLO client.example.org\r\n")
			readGreetingReply(t, scanner, "250")
			c := <-connections
			c.SetSessionDeadline(time.Now().Add(-time.Second))
			io.WriteString(conn, command+"\r\nNOOP\r\n")
			if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), "421 4.4.2 ") {
				t.Fatalf("want 421 4.4.2, got %q (%v)", scanner.Text(), scanner.Err())
			}
			if scanner.Scan() {
				t.Fatalf("extra reply after deadline: %q", scanner.Text())
			}
		})
	}
}

func TestSessionDeadlineCanExtendAndDisable(t *testing.T) {
	connections := make(chan *smtp.Conn, 1)
	_, server, conn, scanner := testServer(t, func(s *smtp.Server) {
		s.Backend = smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) { connections <- c; return ctxSession{}, nil })
	})
	defer server.Close()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	readGreetingReply(t, scanner, "220")
	io.WriteString(conn, "EHLO client.example.org\r\n")
	readGreetingReply(t, scanner, "250")
	c := <-connections
	for _, next := range []time.Time{time.Now().Add(time.Minute), {}} {
		c.SetSessionDeadline(time.Now().Add(-time.Second))
		c.SetSessionDeadline(next)
		io.WriteString(conn, "NOOP\r\n")
		readGreetingReply(t, scanner, "250")
	}
}

func TestSessionDeadlineSurvivesSTARTTLSBeforeNewEHLO(t *testing.T) {
	connections := make(chan *smtp.Conn, 1)
	_, server, conn, scanner := testServer(t, func(s *smtp.Server) {
		s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{generateTestCert()}}
		s.Backend = smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) { connections <- c; return ctxSession{}, nil })
	})
	defer server.Close()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	readGreetingReply(t, scanner, "220")
	io.WriteString(conn, "EHLO client.example.org\r\n")
	readGreetingReply(t, scanner, "250")
	c := <-connections
	io.WriteString(conn, "STARTTLS\r\n")
	readGreetingReply(t, scanner, "220")
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	scanner = bufio.NewScanner(tlsConn)
	c.SetSessionDeadline(time.Now().Add(-time.Second))
	io.WriteString(tlsConn, "NOOP\r\n")
	readGreetingReply(t, scanner, "421")
	if scanner.Scan() {
		t.Fatalf("extra reply after timeout: %q", scanner.Text())
	}
}
