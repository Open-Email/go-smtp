package smtp

import (
	"testing"
)

// EHLO keywords are case-insensitive (RFC 5321 §4.1.1.1, and §2.4: "verbs
// and argument values ... are not case sensitive"). The parser kept the
// server's spelling while every lookup is in upper case, so an extension
// advertised in lower or mixed case was treated as absent: STARTTLS among
// them, which left the session in plaintext.

const mixedCaseEHLO = "220 hello\n" +
	"250-mx at your service\n" +
	"250-starttls\n" +
	"250-8bitmime\n" +
	"250-Size 1000\n" +
	"250-Auth plain LOGIN\n" +
	"250 SmtpUtf8\n"

func TestEHLOKeywordsAreCaseInsensitive(t *testing.T) {
	c := NewClient(newScriptedConn(mixedCaseEHLO))
	if err := c.Hello("r5.out.example"); err != nil {
		t.Fatalf("Hello: %v", err)
	}
	for _, ext := range []string{"STARTTLS", "starttls", "8BITMIME", "SMTPUTF8", "SIZE", "AUTH"} {
		if ok, _ := c.Extension(ext); !ok {
			t.Errorf("Extension(%q) = false, want true", ext)
		}
	}
	if size, ok := c.MaxMessageSize(); !ok || size != 1000 {
		t.Errorf("MaxMessageSize = %d, %v; want 1000, true", size, ok)
	}
	if !c.SupportsAuth("PLAIN") || !c.SupportsAuth("login") {
		t.Error("SupportsAuth does not see the mixed-case AUTH keyword's mechanisms")
	}
	// The parameter keeps the server's spelling: only the keyword is folded.
	if _, param := c.Extension("AUTH"); param != "plain LOGIN" {
		t.Errorf("AUTH parameter = %q, want the server's %q", param, "plain LOGIN")
	}
}

func TestMailUsesMixedCaseExtensions(t *testing.T) {
	conn := newScriptedConn(mixedCaseEHLO + "250 sender ok\n")
	c := NewClient(conn)
	if err := c.Hello("r5.out.example"); err != nil {
		t.Fatalf("Hello: %v", err)
	}
	if err := c.Mail("a@sender.example", &MailOptions{UTF8: true, Size: 10}); err != nil {
		t.Fatalf("Mail: %v", err)
	}
	want := "EHLO r5.out.example\nMAIL FROM:<a@sender.example> BODY=8BITMIME SIZE=10 SMTPUTF8\n"
	if got := conn.commands(); got != want {
		t.Errorf("client wrote:\n%s\nwant:\n%s", got, want)
	}
}

func TestLowerCaseSTARTTLSIsStarted(t *testing.T) {
	for name, construct := range map[string]func(*scriptedConn) (*Client, error){
		"NewClientStartTLSWithName": func(conn *scriptedConn) (*Client, error) {
			return NewClientStartTLSWithName(conn, nil, "r5.out.example")
		},
		"NewClientStartTLSIfOfferedWithName": func(conn *scriptedConn) (*Client, error) {
			c, started, err := NewClientStartTLSIfOfferedWithName(conn, nil, "r5.out.example")
			if err == nil && !started {
				t.Error("started = false for a server that offered starttls")
			}
			return c, err
		},
	} {
		t.Run(name, func(t *testing.T) {
			conn := newScriptedConn("220 hello\n" + "250-mx at your service\n" + "250 StartTLS\n" + "220 go ahead\n")
			c, err := construct(conn)
			if err != nil || c == nil {
				t.Fatalf("constructor = %v, %v; want a client after STARTTLS", c, err)
			}
			if got, want := conn.commands(), "EHLO r5.out.example\nSTARTTLS\n"; got != want {
				t.Errorf("client wrote:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}
