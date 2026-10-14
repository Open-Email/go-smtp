package smtp_test

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"strings"
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
