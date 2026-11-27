package smtp

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

type tlsShutdownRecordingConn struct {
	net.Conn
	bytesRead int
}

func (c *tlsShutdownRecordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.bytesRead += n
	return n, err
}

func TestQuitTLSShutdown(t *testing.T) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, command, reply string
		wantCode             int
		wantAlert            bool
		peerSendsAlert       bool
		quitTimeout          time.Duration
	}{
		{name: "peer replies with close_notify", command: "QUIT\r\n", reply: "221 bye\r\n", wantAlert: true, peerSendsAlert: true},
		{name: "peer omits close_notify", command: "QUIT\r\n", reply: "221 bye\r\n", wantAlert: true, quitTimeout: 100 * time.Millisecond},
		{name: "421 on MAIL", command: "MAIL FROM:<sender@example.com>\r\n", reply: "421 closing\r\n", wantCode: 421, wantAlert: true},
		{name: "421 on QUIT", command: "QUIT\r\n", reply: "421 closing\r\n", wantCode: 421, wantAlert: true},
		{name: "MAIL response timeout", command: "MAIL FROM:<sender@example.com>\r\n", wantAlert: true},
		{name: "malformed MAIL reply", command: "MAIL FROM:<sender@example.com>\r\n", reply: "invalid reply\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			serverSide.SetDeadline(time.Now().Add(3 * time.Second))
			serverDone := make(chan error, 1)
			go func() {
				serverDone <- func() error {
					raw := &tlsShutdownRecordingConn{Conn: serverSide}
					s := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}})
					r := bufio.NewReader(s)
					if _, err := io.WriteString(s, "220 hello\r\n"); err != nil {
						return err
					}
					if line, err := r.ReadString('\n'); err != nil || line != "EHLO sender.example\r\n" {
						return fmt.Errorf("EHLO = %q, %v", line, err)
					}
					if _, err := io.WriteString(s, "250 hello\r\n"); err != nil {
						return err
					}
					if line, err := r.ReadString('\n'); err != nil || line != tt.command {
						return fmt.Errorf("command = %q, %v; want %q", line, err, tt.command)
					}
					if tt.reply != "" {
						if _, err := io.WriteString(s, tt.reply); err != nil {
							return err
						}
					}

					// Go TLS also reports EOF for a bare transport close. Check
					// that the server read a TLS record before reporting EOF.
					raw.bytesRead = 0
					if b, err := r.ReadByte(); err != io.EOF {
						return fmt.Errorf("server TLS read = %q, %v; want EOF", b, err)
					}
					if gotAlert := raw.bytesRead > 0; gotAlert != tt.wantAlert {
						return fmt.Errorf("client sent close_notify = %v; want %v", gotAlert, tt.wantAlert)
					}
					if tt.peerSendsAlert {
						// net.Pipe writes only complete once the peer reads them.
						if err := s.CloseWrite(); err != nil {
							return fmt.Errorf("client did not read the server close_notify: %w", err)
						}
					}
					return nil
				}()
			}()

			c := NewClient(tls.Client(clientSide, &tls.Config{InsecureSkipVerify: true}))
			c.CommandTimeout = time.Second
			c.QuitTimeout = time.Second
			if tt.quitTimeout != 0 {
				c.QuitTimeout = tt.quitTimeout
			}
			if err := c.Hello("sender.example"); err != nil {
				t.Fatalf("Hello: %v", err)
			}
			var opErr error
			if tt.command == "QUIT\r\n" {
				start := time.Now()
				opErr = c.Quit()
				if elapsed := time.Since(start); tt.quitTimeout != 0 && elapsed > 500*time.Millisecond {
					t.Errorf("Quit took %v with timeout %v", elapsed, tt.quitTimeout)
				}
			} else {
				c.CommandTimeout = 50 * time.Millisecond
				opErr = c.Mail("sender@example.com", nil)
				if err := c.Quit(); err != nil {
					t.Errorf("Quit after MAIL failure: %v", err)
				}
			}
			var smtpErr *SMTPError
			var netErr net.Error
			switch {
			case tt.wantCode != 0:
				if !errors.As(opErr, &smtpErr) || smtpErr.Code != tt.wantCode {
					t.Errorf("command error = %v; want SMTP %d", opErr, tt.wantCode)
				}
			case tt.reply == "":
				if !errors.As(opErr, &netErr) || !netErr.Timeout() {
					t.Errorf("command error = %v; want timeout", opErr)
				}
			case tt.wantAlert:
				if opErr != nil {
					t.Errorf("Quit: %v", opErr)
				}
			case opErr == nil:
				t.Error("MAIL succeeded with a malformed reply")
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}
