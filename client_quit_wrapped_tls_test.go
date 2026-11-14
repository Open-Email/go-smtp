package smtp

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// A connection decorator should not need to expose TLS-specific methods for
// Quit to honor its timeout. Logging and metrics connections commonly embed
// only net.Conn in this way.
type quitTLSDecorator struct{ net.Conn }

func TestQuitTimeoutIncludesWrappedTLSClose(t *testing.T) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, wrapped := range []bool{false, true} {
		for _, reply := range []bool{false, true} {
			t.Run(fmt.Sprintf("wrapped=%v/reply=%v", wrapped, reply), func(t *testing.T) {
				clientSide, serverSide := net.Pipe()
				defer clientSide.Close()
				defer serverSide.Close()
				release := make(chan struct{})
				defer close(release)
				serverDone := make(chan error, 1)
				go func() {
					serverSide.SetDeadline(time.Now().Add(10 * time.Second))
					s := tls.Server(serverSide, &tls.Config{Certificates: []tls.Certificate{cert}})
					r := bufio.NewReader(s)
					if _, err := io.WriteString(s, "220 hello\r\n"); err != nil {
						serverDone <- err
						return
					}
					if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "EHLO ") {
						serverDone <- fmt.Errorf("EHLO = %q, %v", line, err)
						return
					}
					if _, err := io.WriteString(s, "250 hello\r\n"); err != nil {
						serverDone <- err
						return
					}
					if line, err := r.ReadString('\n'); err != nil || line != "QUIT\r\n" {
						serverDone <- fmt.Errorf("QUIT = %q, %v", line, err)
						return
					}
					if reply {
						if _, err := io.WriteString(s, "221 bye\r\n"); err != nil {
							serverDone <- err
							return
						}
					}
					serverDone <- nil
					// Do not read the TLS close_notify: the timeout must still
					// end the connection, even after a successful QUIT reply.
					<-release
				}()

				var conn net.Conn = tls.Client(clientSide, &tls.Config{InsecureSkipVerify: true})
				if wrapped {
					conn = &quitTLSDecorator{Conn: conn}
				}
				c := NewClient(conn)
				c.CommandTimeout = time.Second
				c.QuitTimeout = 40 * time.Millisecond
				if err := c.Hello("sender.example"); err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				err := c.Quit()
				elapsed := time.Since(start)
				t.Logf("QuitTimeout = %v; elapsed = %v; error = %v", c.QuitTimeout, elapsed, err)
				if err == nil {
					t.Error("Quit returned nil although connection cleanup could not complete")
				}
				if elapsed > time.Second {
					t.Errorf("Quit exceeded its %v timeout: %v", c.QuitTimeout, elapsed)
				}
				select {
				case err := <-serverDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("server did not finish the QUIT exchange")
				}
				serverSide.SetReadDeadline(time.Now().Add(time.Second))
				if n, err := serverSide.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
					t.Errorf("transport Read = %d, %v; want EOF after Quit", n, err)
				}
			})
		}
	}
}
