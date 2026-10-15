package smtp

import (
	"context"
	"io"

	"github.com/emersion/go-sasl"
)

var (
	ErrAuthFailed = &SMTPError{
		Code:         535,
		EnhancedCode: EnhancedCode{5, 7, 8},
		Message:      "Authentication failed",
	}
	ErrAuthRequired = &SMTPError{
		Code:         502,
		EnhancedCode: EnhancedCode{5, 7, 0},
		Message:      "Please authenticate first",
	}
	ErrAuthUnsupported = &SMTPError{
		Code:         502,
		EnhancedCode: EnhancedCode{5, 7, 0},
		Message:      "Authentication not supported",
	}
	ErrAuthUnknownMechanism = &SMTPError{
		Code:         504,
		EnhancedCode: EnhancedCode{5, 7, 4},
		Message:      "Unsupported authentication mechanism",
	}
)

// A SMTP server backend.
type Backend interface {
	NewSession(c *Conn) (Session, error)
}

// BackendFunc is an adapter to allow the use of an ordinary function as a
// Backend.
type BackendFunc func(c *Conn) (Session, error)

var _ Backend = (BackendFunc)(nil)

// NewSession calls f(c).
func (f BackendFunc) NewSession(c *Conn) (Session, error) {
	return f(c)
}

// Session is used by servers to respond to an SMTP client.
//
// The methods are called when the remote client issues the matching command.
//
// Mail, Rcpt and Data receive a per-command context derived from the
// connection's context (see Conn.Context): it is cancelled when the command
// finishes, when the transaction is aborted mid-command (RSET or connection
// close during a chunked BDAT transfer) or when the server is closed or shut
// down. A client disconnect is only detected between commands, so it does
// not cancel the context while a backend call is still in flight. Backends
// should propagate the context into their I/O (database queries, upstream
// deliveries) and may layer their own deadlines on top of it.
type Session interface {
	// Discard currently processed message.
	Reset()

	// Free all resources associated with session.
	//
	// Logout is called when:
	// - The client issues QUIT
	// - The connection is closed
	// - The client issues STARTTLS (before creating a new session)
	// - The client issues re-EHLO/re-HELO/re-LHLO (before creating a new
	//   session), unless GreetingSession.CheckGreeting refused it
	Logout() error

	// Set return path for currently processed message.
	Mail(ctx context.Context, from string, opts *MailOptions) error
	// Add recipient for currently processed message.
	Rcpt(ctx context.Context, to string, opts *RcptOptions) error
	// Set currently processed message contents and send it.
	//
	// r must be consumed before Data returns.
	Data(ctx context.Context, r io.Reader) error
}

// LMTPSession is an add-on interface for Session. It can be implemented by
// LMTP servers to provide extra functionality.
type LMTPSession interface {
	Session

	// LMTPData is the LMTP-specific version of Data method.
	// It can be optionally implemented by the backend to provide
	// per-recipient status information when it is used over LMTP
	// protocol.
	//
	// LMTPData implementation sets status information using passed
	// StatusCollector by calling SetStatus once per each AddRcpt
	// call, even if AddRcpt was called multiple times with
	// the same argument. SetStatus must not be called after
	// LMTPData returns.
	//
	// Return value of LMTPData itself is used as a status for
	// recipients that got no status set before using StatusCollector.
	//
	// ctx carries the same per-command context as Session.Data.
	LMTPData(ctx context.Context, r io.Reader, status StatusCollector) error
}

// GreetingSession is an add-on interface for Session. A repeated HELO, EHLO or
// LHLO replaces the current session: the server calls Logout, resets the
// transaction and calls Backend.NewSession again. Before any of that it calls
// CheckGreeting on the current session with the new domain; an error is sent
// to the client (a *SMTPError as is, anything else as 451 4.0.0) and the
// session, the greeting and any mail transaction stay exactly as they were, as
// RFC 5321 section 4.1.4 requires after a refused EHLO.
//
// Conn.Hostname and Conn.Greeting still report the current greeting during
// the call. CheckGreeting is not called for a connection's first greeting, nor
// for the first one after STARTTLS: there is no session to keep then, and
// Backend.NewSession returning an error already refuses the greeting.
type GreetingSession interface {
	Session

	// ctx carries the same per-command context as Session.Mail.
	CheckGreeting(ctx context.Context, domain string) error
}

// StatusCollector allows a backend to provide per-recipient status
// information.
type StatusCollector interface {
	SetStatus(rcptTo string, err error)
}

// AuthSession is an add-on interface for Session. It provides support for the
// AUTH extension.
type AuthSession interface {
	Session

	AuthMechanisms() []string
	Auth(mech string) (sasl.Server, error)
}

// XCLIENTBackend is an add-on interface for Session. It provides support for the
// XCLIENT extension.
type XCLIENTBackend interface {
	// XCLIENT handles the XCLIENT command. The attrs parameter contains
	// the connection attributes provided by the client (ADDR, PORT, PROTO,
	// HELO, LOGIN, NAME). Backends can validate and process these attributes.
	// If an error is returned, the XCLIENT command will be rejected.
	XCLIENT(session Session, attrs map[string]string) error
}
