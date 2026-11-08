package smtp_test

import (
	"io"
	"strings"
	"testing"
	"time"
)

// A client that authenticates and then greets again stays authenticated. RFC 5321 lets a
// client send EHLO later in the session, and that resets the server only as RSET does. RFC
// 4954 §4 keeps the login for the rest of the session: a further AUTH MUST get 503. So a
// client that follows both sends its mail straight after the second EHLO, without
// authenticating again.
//
// Replacing the backend session after AUTH would create one that never saw Auth,
// while the connection stays marked as authenticated. The client could not log in
// again (503), and mail would reach a session that treats it as anonymous. This
// test uses the default backend without an optional greeting hook.
func TestServer_AuthSurvivesReEhlo(t *testing.T) {
	be, s, c, scanner, _ := testServerEhlo(t)
	defer s.Close()
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))

	const auth = "AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk\r\n"
	expect := func(cmd, code string) {
		t.Helper()
		io.WriteString(c, cmd)
		if line := readResponseLine(t, scanner); !strings.HasPrefix(line, code+" ") {
			t.Fatalf("%s: got %q, want %s", strings.TrimSpace(cmd), line, code)
		}
	}

	expect(auth, "235")

	io.WriteString(c, "EHLO localhost\r\n")
	for {
		line := readResponseLine(t, scanner)
		if strings.HasPrefix(line, "250 ") {
			break
		}
		if !strings.HasPrefix(line, "250-") {
			t.Fatalf("EHLO: %q", line)
		}
	}

	// The login is kept, so a second AUTH is refused (RFC 4954 §4).
	expect(auth, "503")

	expect("MAIL FROM:<root@nsa.gov>\r\n", "250")
	expect("RCPT TO:<root@gchq.gov.uk>\r\n", "250")
	expect("DATA\r\n", "354")
	expect("Hey <3\r\n.\r\n", "250")

	if len(be.messages) != 1 || len(be.anonmsgs) != 0 {
		t.Fatalf("after AUTH and a second EHLO, %d message(s) were accepted as authenticated and %d as anonymous; want 1 and 0",
			len(be.messages), len(be.anonmsgs))
	}
}
