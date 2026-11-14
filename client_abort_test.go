package smtp

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stalledTLSServer speaks SMTP over TLS on serverSide up to EHLO, reads one
// more command line and then stops reading and writing, like a peer whose
// receive window is full. net.Pipe has no buffer, so any later client write,
// including the close_notify alert of a TLS close, blocks until its deadline.
// gotCommand is closed once that last command has been read.
func stalledTLSServer(t *testing.T, serverSide net.Conn) (gotCommand chan struct{}) {
	t.Helper()
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatal(err)
	}
	gotCommand = make(chan struct{})
	release := make(chan struct{})
	serverDone := make(chan error, 1)
	t.Cleanup(func() {
		close(release)
		serverSide.Close()
		if err := <-serverDone; err != nil {
			t.Errorf("stalled TLS server: %v", err)
		}
	})
	go func() {
		serverDone <- func() error {
			s := tls.Server(serverSide, &tls.Config{Certificates: []tls.Certificate{cert}})
			r := bufio.NewReader(s)
			if _, err := s.Write([]byte("220 hello\r\n")); err != nil {
				return err
			}
			if _, err := r.ReadString('\n'); err != nil { // EHLO
				return err
			}
			if _, err := s.Write([]byte("250 hello\r\n")); err != nil {
				return err
			}
			if _, err := r.ReadString('\n'); err != nil { // the command left unanswered
				return err
			}
			close(gotCommand)
			<-release
			return nil
		}()
	}()
	return gotCommand
}

// ioTrackingConn counts the Read and Write calls in progress on a connection,
// so a test can wait until the client is parked in a Read with no Write under
// way. crypto/tls skips close_notify when a Write is in flight at Close, and a
// Write on a net.Pipe returns a moment after the peer has read it.
type ioTrackingConn struct {
	net.Conn
	reads, writes atomic.Int32
	// afterExpiredDeadline, if set, runs once, after the first SetDeadline
	// that lies in the past (Abort's) has been applied.
	afterExpiredDeadline func()
	expiredOnce          sync.Once
}

func (c *ioTrackingConn) SetDeadline(d time.Time) error {
	err := c.Conn.SetDeadline(d)
	if c.afterExpiredDeadline != nil && !d.IsZero() && d.Before(time.Now()) {
		c.expiredOnce.Do(c.afterExpiredDeadline)
	}
	return err
}

func (c *ioTrackingConn) Read(b []byte) (int, error) {
	c.reads.Add(1)
	defer c.reads.Add(-1)
	return c.Conn.Read(b)
}

func (c *ioTrackingConn) Write(b []byte) (int, error) {
	c.writes.Add(1)
	defer c.writes.Add(-1)
	return c.Conn.Write(b)
}

func (c *ioTrackingConn) waitParkedInRead(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for c.reads.Load() == 0 || c.writes.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("client never settled into waiting for a reply")
		}
		time.Sleep(time.Millisecond)
	}
}

// wantTransportClosed fails unless the client closed the connection under TLS.
func wantTransportClosed(t *testing.T, serverSide net.Conn) {
	t.Helper()
	serverSide.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4096)
	for {
		if _, err := serverSide.Read(buf); err != nil {
			if err != io.EOF {
				t.Errorf("underlying transport Read = %v; want io.EOF", err)
			}
			return
		}
	}
}

// crypto/tls allows close_notify 5s; a close that waits for it takes that
// long against a stalled peer, one that does not returns in milliseconds.
const abortBudget = 2 * time.Second

func TestAbortInterruptsCommandOverStalledTLS(t *testing.T) {
	pipeSide, serverSide := net.Pipe()
	defer pipeSide.Close()
	clientSide := &ioTrackingConn{Conn: pipeSide}
	gotCommand := stalledTLSServer(t, serverSide)

	c := NewClient(tls.Client(clientSide, &tls.Config{InsecureSkipVerify: true}))
	c.CommandTimeout = time.Minute
	if err := c.Hello("sender.example"); err != nil {
		t.Fatalf("Hello: %v", err)
	}
	mailErr := make(chan error, 1)
	go func() { mailErr <- c.Mail("sender@example.com", nil) }()
	<-gotCommand
	clientSide.waitParkedInRead(t)

	start := time.Now()
	if err := c.Abort(); err != nil {
		t.Errorf("Abort = %v; want nil", err)
	}
	if elapsed := time.Since(start); elapsed > abortBudget {
		t.Errorf("Abort took %v; it waited for TLS close_notify", elapsed)
	}
	select {
	case err := <-mailErr:
		if err == nil {
			t.Error("Mail returned nil after Abort; want an error")
		}
		var smtpErr *SMTPError
		if errors.As(err, &smtpErr) {
			t.Errorf("Mail = %v; want a transport error, not an SMTP reply", err)
		}
	case <-time.After(abortBudget):
		t.Fatal("Mail still waiting for its reply after Abort")
	}
	wantTransportClosed(t, serverSide)

	if err := c.Abort(); err != nil {
		t.Errorf("second Abort = %v; want nil", err)
	}
	if err := c.Quit(); err != nil {
		t.Errorf("Quit after Abort = %v; want nil", err)
	}
}

// Quit ends with a Close of its own. An Abort that arrives while Quit waits
// for 221 wakes that wait, and must still hold when Quit's Close then wins the
// race to be the one closing: crypto/tls gives that Close a fresh 5s write
// deadline for close_notify after Abort has set its expired one.
func TestAbortDuringQuitOverStalledTLS(t *testing.T) {
	pipeSide, serverSide := net.Pipe()
	defer pipeSide.Close()
	// Hold Abort right after its expired deadline has woken Quit, so that
	// Quit's own Close is the one that gets to close the TLS connection.
	clientSide := &ioTrackingConn{Conn: pipeSide, afterExpiredDeadline: func() { time.Sleep(50 * time.Millisecond) }}
	gotCommand := stalledTLSServer(t, serverSide)

	c := NewClient(tls.Client(clientSide, &tls.Config{InsecureSkipVerify: true}))
	c.CommandTimeout = time.Minute
	c.QuitTimeout = time.Minute
	if err := c.Hello("sender.example"); err != nil {
		t.Fatalf("Hello: %v", err)
	}
	quitDone := make(chan struct{})
	go func() {
		defer close(quitDone)
		c.Quit()
	}()
	<-gotCommand
	clientSide.waitParkedInRead(t)

	start := time.Now()
	if err := c.Abort(); err != nil {
		t.Errorf("Abort = %v; want nil", err)
	}
	select {
	case <-quitDone:
	case <-time.After(abortBudget):
		t.Fatalf("Quit still running %v after Abort; its Close waited for TLS close_notify", time.Since(start))
	}
	if elapsed := time.Since(start); elapsed > abortBudget {
		t.Errorf("Abort and Quit took %v; a close waited for TLS close_notify", elapsed)
	}
	wantTransportClosed(t, serverSide)
}

func TestAbortPlaintextSendsNothing(t *testing.T) {
	conn := newScriptedConn("220 hello\r\n250 hello\r\n")
	c := NewClient(conn)
	if err := c.Hello("localhost"); err != nil {
		t.Fatalf("Hello: %v", err)
	}
	if err := c.Abort(); err != nil {
		t.Errorf("Abort = %v; want nil", err)
	}
	if got, want := conn.commands(), "EHLO localhost\n"; got != want {
		t.Errorf("client wrote %q; want %q (no QUIT)", got, want)
	}
	if !conn.closed {
		t.Error("Abort left the connection open")
	}
}
