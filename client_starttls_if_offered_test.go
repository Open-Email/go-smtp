package smtp

import (
	"errors"
	"testing"
)

// A client that delivers without TLS when the server has none must not need
// a second connection to find that out: NewClientStartTLSWithName says QUIT
// when STARTTLS is not offered, so a caller falling back to plaintext showed
// the server two sessions per message, "EHLO, QUIT" and then the delivery.

func TestStartTLSIfOfferedKeepsTheSessionWhenItIsNot(t *testing.T) {
	conn := newScriptedConn("220 hello\n" +
		"250-mx at your service\n" + "250 8BITMIME\n" + // EHLO, no STARTTLS
		"250 sender ok\n" + "250 rcpt ok\n" + "221 bye\n")
	c, started, err := NewClientStartTLSIfOfferedWithName(conn, nil, "r5.out.example")
	if err != nil || c == nil {
		t.Fatalf("NewClientStartTLSIfOfferedWithName = %v, %v; want the client", c, err)
	}
	if started {
		t.Error("started = true for a server that offers no STARTTLS")
	}
	if conn.closed {
		t.Fatal("the connection was closed")
	}
	if _, ok := c.TLSConnectionState(); ok {
		t.Error("the session claims TLS")
	}
	// The session goes on where EHLO left it, on the same connection.
	if err := c.Mail("a@sender.example", nil); err != nil {
		t.Fatalf("Mail: %v", err)
	}
	if err := c.Rcpt("b@rcpt.example", nil); err != nil {
		t.Fatalf("Rcpt: %v", err)
	}
	if err := c.Quit(); err != nil {
		t.Fatalf("Quit: %v", err)
	}
	want := "EHLO r5.out.example\nMAIL FROM:<a@sender.example> BODY=8BITMIME\nRCPT TO:<b@rcpt.example>\nQUIT\n"
	if got := conn.commands(); got != want {
		t.Errorf("client wrote:\n%s\nwant:\n%s", got, want)
	}
}

func TestStartTLSIfOfferedKeepsTheSessionAfterHELO(t *testing.T) {
	// A server without EHLO has no extensions, STARTTLS among them.
	conn := newScriptedConn("220 hello\n" + "502 EH?\n" + "250 hello\n" + "250 sender ok\n")
	c, started, err := NewClientStartTLSIfOfferedWithName(conn, nil, "r5.out.example")
	if err != nil || c == nil || started {
		t.Fatalf("NewClientStartTLSIfOfferedWithName = %v, %v, %v; want the plain client", c, started, err)
	}
	if err := c.Mail("a@sender.example", nil); err != nil {
		t.Fatalf("Mail: %v", err)
	}
	want := "EHLO r5.out.example\nHELO r5.out.example\nMAIL FROM:<a@sender.example>\n"
	if got := conn.commands(); got != want {
		t.Errorf("client wrote:\n%s\nwant:\n%s", got, want)
	}
}

func TestStartTLSIfOfferedStartsItWhenItIs(t *testing.T) {
	conn := newScriptedConn("220 hello\n" + "250-mx at your service\n" + "250 STARTTLS\n" + "220 go ahead\n")
	c, started, err := NewClientStartTLSIfOfferedWithName(conn, nil, "r5.out.example")
	if err != nil || c == nil {
		t.Fatalf("NewClientStartTLSIfOfferedWithName = %v, %v; want the client", c, err)
	}
	if !started {
		t.Error("started = false for a server that accepted STARTTLS")
	}
	if got, want := conn.commands(), "EHLO r5.out.example\nSTARTTLS\n"; got != want {
		t.Errorf("client wrote:\n%s\nwant:\n%s", got, want)
	}
}

// Every failure is the one NewClientStartTLSWithName reports, ended the same
// way: QUIT while the server is still listening, a plain close otherwise.
func TestStartTLSIfOfferedFailsLikeTheStrictConstructor(t *testing.T) {
	for name, tc := range map[string]struct {
		server, want string
	}{
		"STARTTLS refused": {
			server: "220 hello\n" + "250-mx at your service\n" + "250 STARTTLS\n" + "454 TLS not available\n" + "221 bye\n",
			want:   "EHLO r5.out.example\nSTARTTLS\nQUIT\n",
		},
		"STARTTLS answered with 421": {
			server: "220 hello\n" + "250-mx at your service\n" + "250 STARTTLS\n" + "421 closing\n",
			want:   "EHLO r5.out.example\nSTARTTLS\n",
		},
		"EHLO refused": {
			server: "220 hello\n" + "550 access denied\n" + "221 bye\n",
			want:   "EHLO r5.out.example\nQUIT\n",
		},
		"EHLO answered with 421": {
			server: "220 hello\n" + "421 closing\n",
			want:   "EHLO r5.out.example\n",
		},
		"554 greeting": {
			server: "554 5.7.1 your IP is listed\n" + "221 bye\n",
			want:   "QUIT\n",
		},
		"STARTTLS answered with 250": {
			server: "220 hello\n" + "250-mx\n250 STARTTLS\n" + "250 not 220\n" + "221 bye\n",
			want:   "EHLO r5.out.example\nSTARTTLS\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			conn := newScriptedConn(tc.server)
			c, started, err := NewClientStartTLSIfOfferedWithName(conn, nil, "r5.out.example")
			if err == nil || c != nil || started {
				t.Fatalf("NewClientStartTLSIfOfferedWithName = %v, %v, %v; want a setup error", c, started, err)
			}
			if errors.Is(err, ErrSTARTTLSUnsupported) {
				t.Errorf("error = %v: the lenient constructor never reports STARTTLS as unsupported", err)
			}
			if got := conn.commands(); got != tc.want {
				t.Errorf("client wrote:\n%s\nwant:\n%s", got, tc.want)
			}
			if !conn.closed {
				t.Error("connection left open after the setup failed")
			}
		})
	}
}

func TestStartTLSIfOfferedRefusesABadLocalName(t *testing.T) {
	conn := newScriptedConn("220 hello\n")
	c, started, err := NewClientStartTLSIfOfferedWithName(conn, nil, "host\ninjection")
	if err == nil || c != nil || started {
		t.Fatalf("NewClientStartTLSIfOfferedWithName = %v, %v, %v; want an error", c, started, err)
	}
	if got := conn.commands(); got != "" {
		t.Errorf("client wrote %q before refusing the name", got)
	}
}

// started promises the STARTTLS command was accepted, not that TLS works: the
// handshake runs on the next I/O, and its error comes from that command.
func TestStartTLSIfOfferedHandshakeRunsOnTheNextCommand(t *testing.T) {
	// After "220 go ahead" the server sends plaintext, not a TLS ServerHello.
	conn := newScriptedConn("220 hello\n" + "250-mx at your service\n" + "250 STARTTLS\n" + "220 go ahead\n" + "250 not TLS\n")
	c, started, err := NewClientStartTLSIfOfferedWithName(conn, nil, "r5.out.example")
	if err != nil || c == nil || !started {
		t.Fatalf("NewClientStartTLSIfOfferedWithName = %v, %v, %v; want a started client", c, started, err)
	}
	if state, ok := c.TLSConnectionState(); !ok || state.HandshakeComplete {
		t.Fatalf("TLSConnectionState = %+v, %v; want a TLS connection whose handshake has not run", state, ok)
	}
	if err := c.Hello("r5.out.example"); err == nil {
		t.Fatal("Hello succeeded over a connection whose TLS handshake cannot complete")
	}
	if state, _ := c.TLSConnectionState(); state.HandshakeComplete {
		t.Error("handshake reported complete after it failed")
	}
}
