package smtp

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type tlsShutdownTCPConn struct {
	*net.TCPConn
	peerSendingAlert <-chan struct{}
	readPeerAlert    atomic.Bool
}

func (c *tlsShutdownTCPConn) Read(p []byte) (int, error) {
	n, err := c.TCPConn.Read(p)
	if n > 0 {
		select {
		case <-c.peerSendingAlert:
			c.readPeerAlert.Store(true)
		default:
		}
	}
	return n, err
}

func TestQuitTLSHalfClosesTCPBeforeReadingPeerAlert(t *testing.T) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatal(err)
	}
	listener := newLocalListener(t)
	defer listener.Close()

	peerSendingAlert := make(chan struct{})
	peerDone := make(chan error, 1)
	go func() {
		peerDone <- func() error {
			conn, err := listener.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return err
			}
			raw := &tlsShutdownRecordingConn{Conn: conn}
			s := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}})
			r := bufio.NewReader(s)
			if _, err := io.WriteString(s, "220 hello\r\n"); err != nil {
				return err
			}
			if line, err := r.ReadString('\n'); err != nil || line != "QUIT\r\n" {
				return fmt.Errorf("command = %q, %v; want QUIT", line, err)
			}
			if _, err := io.WriteString(s, "221 bye\r\n"); err != nil {
				return err
			}
			raw.bytesRead = 0
			if _, err := r.ReadByte(); err != io.EOF || raw.bytesRead == 0 {
				return fmt.Errorf("server TLS read = %v after reading %d wire bytes; want client close_notify", err, raw.bytesRead)
			}
			// This peer sends its alert only after receiving the client's TCP FIN.
			if n, err := conn.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				return fmt.Errorf("server TCP read = %d, %v; want EOF", n, err)
			}
			close(peerSendingAlert)
			return s.CloseWrite()
		}()
	}()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw := &tlsShutdownTCPConn{TCPConn: conn.(*net.TCPConn), peerSendingAlert: peerSendingAlert}
	c := NewClient(tls.Client(raw, &tls.Config{InsecureSkipVerify: true}))
	c.QuitTimeout = 5 * time.Second
	if err := c.Quit(); err != nil {
		t.Errorf("Quit: %v", err)
	}
	if err := <-peerDone; err != nil {
		t.Errorf("peer shutdown: %v", err)
	}
	if !raw.readPeerAlert.Load() {
		t.Error("client did not read the peer's alert after sending TCP FIN")
	}
	if err := conn.SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Errorf("client TCP SetDeadline after Quit = %v; want net.ErrClosed", err)
	}
}
