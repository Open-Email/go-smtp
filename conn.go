package smtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
)

// Number of errors we'll tolerate per connection before closing. Defaults to 3.
const errThreshold = 3

// Number of failed AUTH attempts we'll tolerate per connection before
// closing. RFC 4954 recommends limiting these to slow down online
// brute-force attacks against credentials.
const maxAuthFailures = 3

type Conn struct {
	conn               net.Conn
	text               *textproto.Conn
	server             *Server
	helo               string
	greeting           string    // guarded by locker
	sessionDeadline    time.Time // guarded by locker; persists across greeting/TLS resets
	sessionDeadlineSet bool      // also remember an explicit disable, to clear old read deadlines

	// Number of errors witnessed on this connection
	errCount int

	// Number of failed AUTH attempts witnessed on this connection
	authFailures int

	// First error encountered while writing a response. Once set, the serve
	// loop tears the connection down: the client can no longer observe
	// replies, so processing further commands is pointless. Only accessed
	// from the connection's serve goroutine.
	writeFailure error

	session    Session
	locker     sync.Mutex
	binarymime bool

	// Serializes the backend's Session.Reset and Session.Logout callbacks
	// against each other; see resetSession and logoutSession. Deliberately
	// separate from locker: backends may call locked Conn accessors from
	// inside those callbacks, so locker must never be held across one, yet
	// they still must not run concurrently — Server.Close calls Logout from
	// its own goroutine while the serve goroutine may be in Reset.
	sessionCallbacks sync.Mutex

	// Connection-scoped context, derived from Server.BaseContext (or
	// context.Background) and cancelled when connection handling ends or the
	// server is closed / shut down. Guarded by locker.
	ctx       context.Context
	ctxCancel context.CancelFunc

	bdatPipe      *io.PipeWriter
	bdatCtxCancel context.CancelFunc // cancels the in-flight BDAT command context on abort
	bdatStatus    *statusCollector   // used for BDAT on LMTP
	dataResult    chan error
	bytesReceived int64 // counts total size of chunks when BDAT is used

	fromReceived bool
	recipients   []string
	didAuth      bool

	// XCLIENT data - stores connection information provided by XCLIENT command
	xclientData map[string]string
}

func newConn(c net.Conn, s *Server) *Conn {
	sc := &Conn{
		server: s,
		conn:   c,
	}

	sc.init()
	return sc
}

func (c *Conn) init() {
	// The line-length limit is enforced by readLine on the lines it parses,
	// not by a limiting reader on the raw stream: raw-stream counting would
	// falsely attribute read-ahead bytes (e.g. a pipelined BDAT chunk sitting
	// in the buffer behind its command) to the command line being read.
	rwc := struct {
		io.Reader
		io.Writer
		io.Closer
	}{
		Reader: c.conn,
		Writer: c.conn,
		Closer: c.conn,
	}

	if c.server.Debug != nil {
		rwc = struct {
			io.Reader
			io.Writer
			io.Closer
		}{
			io.TeeReader(rwc.Reader, c.server.Debug),
			io.MultiWriter(rwc.Writer, c.server.Debug),
			rwc.Closer,
		}
	}

	c.text = textproto.NewConn(rwc)

	// Shrink the read buffer so that an over-long line fills it and surfaces
	// as an isPrefix read in readLine after at most MaxLineLength+2 bytes,
	// instead of only once bufio's default 4096-byte buffer fills. This keeps
	// the "500 Too long line" reply eager: it is sent as soon as the limit is
	// exceeded, without waiting for the client to send a newline.
	if lim := c.server.MaxLineLength; lim > 0 && lim+2 < 4096 {
		c.text.R = bufio.NewReaderSize(rwc, lim+2)
	}
}

// Commands are dispatched to the appropriate handler functions.
func (c *Conn) handle(cmd string, arg string) {
	// If panic happens during command handling - send 421 response
	// and close connection.
	defer func() {
		if err := recover(); err != nil {
			c.writeResponse(421, EnhancedCode{4, 0, 0}, "Internal server error")
			c.Close()

			stack := debug.Stack()
			c.server.ErrorLog.Printf("panic serving %v: %v\n%s", c.conn.RemoteAddr(), err, stack)
		}
	}()

	if cmd == "" {
		c.protocolError(500, EnhancedCode{5, 5, 2}, "Error: bad syntax")
		return
	}

	cmd = strings.ToUpper(cmd)
	switch cmd {
	case "SEND", "SOML", "SAML", "EXPN", "HELP", "TURN":
		// These commands are not implemented in any state
		c.writeResponse(502, EnhancedCode{5, 5, 1}, fmt.Sprintf("%v command not implemented", cmd))
	case "HELO", "EHLO", "LHLO":
		lmtp := cmd == "LHLO"
		enhanced := lmtp || cmd == "EHLO"
		if c.server.LMTP && !lmtp {
			c.writeResponse(500, EnhancedCode{5, 5, 1}, "This is a LMTP server, use LHLO")
			return
		}
		if !c.server.LMTP && lmtp {
			c.writeResponse(500, EnhancedCode{5, 5, 1}, "This is not a LMTP server")
			return
		}
		c.handleGreet(enhanced, arg)
	case "MAIL":
		c.handleMail(arg)
	case "RCPT":
		c.handleRcpt(arg)
	case "VRFY":
		c.writeResponse(252, EnhancedCode{2, 5, 0}, "Cannot VRFY user, but will accept message")
	case "NOOP":
		c.writeResponse(250, EnhancedCode{2, 0, 0}, "I have successfully done nothing")
	case "RSET": // Reset session
		c.reset()
		c.writeResponse(250, EnhancedCode{2, 0, 0}, "Session reset")
	case "BDAT":
		c.handleBdat(arg)
	case "DATA":
		c.handleData(arg)
	case "QUIT":
		c.writeResponse(221, EnhancedCode{2, 0, 0}, "Bye")
		c.Close()
	case "AUTH":
		c.handleAuth(arg)
	case "STARTTLS":
		c.handleStartTLS()
	case "XCLIENT":
		c.handleXCLIENT(arg)
	default:
		msg := fmt.Sprintf("Syntax errors, %v command unrecognized", cmd)
		c.protocolError(500, EnhancedCode{5, 5, 2}, msg)
	}
}

func (c *Conn) Server() *Server {
	return c.server
}

// bindContext derives the connection's context from base. It is called by
// Server.Serve before connection handling starts.
func (c *Conn) bindContext(base context.Context) {
	c.locker.Lock()
	defer c.locker.Unlock()
	c.ctx, c.ctxCancel = context.WithCancel(base)
}

// Context returns the connection's context. It is derived from
// Server.BaseContext (or context.Background if unset) and is cancelled when
// connection handling ends — the client disconnected, issued QUIT or caused a
// fatal error — or when the server is closed or shut down.
//
// Backends can capture it in Backend.NewSession and use it to abort
// long-running work (e.g. an upstream delivery) once the result can no longer
// be observed by the client, and to propagate request-scoped values from
// BaseContext into backend calls.
func (c *Conn) Context() context.Context {
	c.locker.Lock()
	defer c.locker.Unlock()
	if c.ctx == nil {
		// Conn was not created through Server.Serve (e.g. tests driving
		// handleConn directly); fall back to a self-contained context.
		c.ctx, c.ctxCancel = context.WithCancel(context.Background())
	}
	return c.ctx
}

// cancelContext cancels the connection's context, if one was created.
func (c *Conn) cancelContext() {
	c.locker.Lock()
	cancel := c.ctxCancel
	c.locker.Unlock()
	if cancel != nil {
		cancel()
	}
}

// withCommandContext runs f with the per-command context passed to
// Session.Mail, Session.Rcpt and Session.Data, derived from the connection's
// context. The context is cancelled when f returns, panic or not.
func (c *Conn) withCommandContext(f func(context.Context) error) error {
	ctx, cancel := context.WithCancel(c.Context())
	defer cancel()
	return f(ctx)
}

func (c *Conn) Session() Session {
	c.locker.Lock()
	defer c.locker.Unlock()
	return c.session
}

// resetSession calls the backend's Session.Reset with no Conn lock held, so
// the callback is free to use any Conn accessor, and serialized against
// logoutSession so a session never sees Reset and Logout at once.
func (c *Conn) resetSession(session Session) {
	c.sessionCallbacks.Lock()
	defer c.sessionCallbacks.Unlock()
	session.Reset()
}

// logoutSession is resetSession's counterpart for Session.Logout.
func (c *Conn) logoutSession(session Session) error {
	c.sessionCallbacks.Lock()
	defer c.sessionCallbacks.Unlock()
	return session.Logout()
}

func (c *Conn) setSession(session Session) {
	c.locker.Lock()
	defer c.locker.Unlock()
	c.session = session
}

func (c *Conn) Close() error {
	// Take what we need under the lock, but call Logout and Close outside of
	// it: backends may call locked Conn accessors (Session, TLSConnectionState,
	// ...) from within Logout, which would deadlock otherwise.
	c.locker.Lock()
	if c.bdatPipe != nil {
		c.bdatPipe.CloseWithError(ErrDataReset)
		c.bdatPipe = nil
	}
	if c.bdatCtxCancel != nil {
		c.bdatCtxCancel()
		c.bdatCtxCancel = nil
	}
	session := c.session
	c.session = nil
	conn := c.conn
	c.locker.Unlock()

	if session != nil {
		c.logoutSession(session)
	}

	return conn.Close()
}

// TLSConnectionState returns the connection's TLS connection state.
// Zero values are returned if the connection doesn't use TLS.
func (c *Conn) TLSConnectionState() (state tls.ConnectionState, ok bool) {
	// c.conn is swapped by handleStartTLS under c.locker; read it under the
	// same lock so callers on other goroutines don't race the swap.
	c.locker.Lock()
	conn := c.conn
	c.locker.Unlock()

	tc, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	return tc.ConnectionState(), true
}

// Greeting returns the current greeting command: HELO, EHLO, or LHLO.
// It is available inside Backend.NewSession and is empty before a greeting,
// after STARTTLS, or if session creation failed.
func (c *Conn) Greeting() string {
	c.locker.Lock()
	defer c.locker.Unlock()
	return c.greeting
}

func (c *Conn) setGreeting(command string) {
	c.locker.Lock()
	defer c.locker.Unlock()
	c.greeting = command
}

func (c *Conn) Hostname() string {
	return c.helo
}

func (c *Conn) Conn() net.Conn {
	c.locker.Lock()
	defer c.locker.Unlock()
	return c.conn
}

func (c *Conn) authAllowed() bool {
	_, isTLS := c.TLSConnectionState()
	return isTLS || c.server.AllowInsecureAuth
}

// protocolError writes errors responses and closes the connection once too many
// have occurred.
func (c *Conn) protocolError(code int, ec EnhancedCode, msg string) {
	c.writeResponse(code, ec, msg)

	c.errCount++
	if c.errCount > errThreshold {
		c.writeResponse(500, EnhancedCode{5, 5, 1}, "Too many errors. Quiting now")
		c.Close()
	}
}

// readError writes the response owed to the client for a failed line read,
// if any, and returns the error the server should report (nil for expected
// conditions such as a clean disconnect, an idle timeout or an over-long
// line).
func (c *Conn) readError(err error) error {
	if err == io.EOF || errors.Is(err, net.ErrClosed) {
		return nil
	}
	if err == ErrTooLongLine {
		c.writeResponse(500, EnhancedCode{5, 4, 0}, "Too long line, closing connection")
		return nil
	}
	if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
		c.writeResponse(421, EnhancedCode{4, 4, 2}, "Idle timeout, bye bye")
		// At most once per connection: both readError call sites are
		// terminal, and a post-Close re-entry takes the ErrClosed branch
		// above before reaching here.
		if h := c.server.OnTimeout; h != nil {
			h()
		}
		return nil
	}
	c.writeResponse(421, EnhancedCode{4, 4, 0}, "Connection error, sorry")
	return err
}

// authFailed writes an authentication error response and closes the
// connection once too many failed AUTH attempts have occurred.
func (c *Conn) authFailed(code int, ec EnhancedCode, err error) {
	c.writeError(code, ec, err)

	c.authFailures++
	if c.authFailures >= maxAuthFailures {
		c.writeResponse(421, EnhancedCode{4, 7, 0}, "Too many failed authentication attempts, closing connection")
		c.Close()
	}
}

// GREET state -> waiting for HELO
func (c *Conn) handleGreet(enhanced bool, arg string) {
	domain, err := parseHelloArgument(arg)
	if err != nil {
		c.writeResponse(501, EnhancedCode{5, 5, 2}, "Domain/address argument required for HELO")
		return
	}
	// c.helo is populated before NewSession so
	// NewSession can access it via Conn.Hostname.
	c.helo = domain
	greeting := "HELO"
	if enhanced {
		greeting = "EHLO"
		if c.server.LMTP {
			greeting = "LHLO"
		}
	}
	c.setGreeting(greeting)

	// RFC 5321: "An EHLO command MAY be issued by a client later in the session"
	// Access the session through the locked accessors: Conn.Close (via
	// Server.Close/Shutdown on another goroutine) writes c.session
	// concurrently.
	if session := c.Session(); session != nil {
		// RFC 5321: "... the SMTP server MUST clear all buffers
		// and reset the state exactly as if a RSET command has been issued."

		// Free session resources before resetting
		if err := c.logoutSession(session); err != nil {
			c.server.ErrorLog.Printf("Failed to logout session on re-EHLO: %v", err)
		}
		c.setSession(nil)
		c.reset()
	}

	// Create new session (whether first EHLO or re-EHLO)
	sess, err := c.server.Backend.NewSession(c)
	if err != nil {
		c.helo = ""
		c.setGreeting("")
		c.writeError(451, EnhancedCode{4, 0, 0}, err)
		return
	}

	c.setSession(sess)

	if !enhanced {
		// RFC 5321 §4.1.1.1: the first element of a HELO reply is the
		// server's domain, not free text.
		c.writeResponse(250, EnhancedCode{2, 0, 0}, c.helloReplyLine(domain))
		return
	}

	caps := []string{
		"PIPELINING",
		"8BITMIME",
		"ENHANCEDSTATUSCODES",
		"CHUNKING",
	}
	if _, isTLS := c.TLSConnectionState(); c.server.TLSConfig != nil && !isTLS {
		caps = append(caps, "STARTTLS")
	}
	if c.authAllowed() {
		mechs := c.authMechanisms()

		authCap := "AUTH"
		for _, name := range mechs {
			authCap += " " + name
		}

		if len(mechs) > 0 {
			caps = append(caps, authCap)
			if c.server.EnableLegacyAuthCap {
				// Obsolete "AUTH=" form for Microsoft clients; see
				// Server.EnableLegacyAuthCap.
				caps = append(caps, "AUTH="+strings.Join(mechs, " "))
			}
		}
	}
	if c.server.EnableSMTPUTF8 {
		caps = append(caps, "SMTPUTF8")
	}
	if _, isTLS := c.TLSConnectionState(); isTLS && c.server.EnableREQUIRETLS {
		caps = append(caps, "REQUIRETLS")
	}
	if c.server.EnableBINARYMIME {
		caps = append(caps, "BINARYMIME")
	}
	if c.server.EnableDSN {
		caps = append(caps, "DSN")
	}
	if c.server.MaxMessageBytes > 0 {
		caps = append(caps, fmt.Sprintf("SIZE %v", c.server.MaxMessageBytes))
	} else {
		caps = append(caps, "SIZE")
	}
	if c.server.MaxRecipients > 0 && !c.server.DisableLimitsCap {
		caps = append(caps, fmt.Sprintf("LIMITS RCPTMAX=%v", c.server.MaxRecipients))
	}
	if c.server.EnableRRVS {
		caps = append(caps, "RRVS")
	}
	if c.server.EnableDELIVERBY {
		if c.server.MinimumDeliverByTime == 0 {
			caps = append(caps, "DELIVERBY")
		} else {
			caps = append(caps, fmt.Sprintf("DELIVERBY %d", int(c.server.MinimumDeliverByTime.Seconds())))
		}
	}
	if c.server.EnableMTPRIORITY {
		if c.server.MtPriorityProfile == PriorityUnspecified {
			caps = append(caps, "MT-PRIORITY")
		} else {
			caps = append(caps, fmt.Sprintf("MT-PRIORITY %s", c.server.MtPriorityProfile))
		}
	}
	if c.server.EnableXCLIENT && c.isXCLIENTTrusted() {
		caps = append(caps, "XCLIENT ADDR PORT PROTO HELO LOGIN NAME")
	}

	// RFC 5321 §4.1.1.1: the first line of an EHLO reply carries the
	// server's domain; the client greeting is trailing text.
	args := []string{c.helloReplyLine(domain)}
	args = append(args, caps...)
	c.writeResponse(250, NoEnhancedCode, args...)
}

// helloReplyLine builds the first line of a HELO/EHLO reply. Per RFC 5321
// §4.1.1.1 it must start with the server's domain; the greeting for the
// client is appended as free text. When Server.Domain is unset, fall back to
// the historical "Hello <client>" form.
func (c *Conn) helloReplyLine(clientDomain string) string {
	if c.server.Domain != "" {
		return fmt.Sprintf("%s Hello %s", c.server.Domain, clientDomain)
	}
	return fmt.Sprintf("Hello %s", clientDomain)
}

// READY state -> waiting for MAIL
func (c *Conn) handleMail(arg string) {
	if c.helo == "" {
		c.writeResponse(502, EnhancedCode{5, 5, 1}, "Please introduce yourself first.")
		return
	}
	if c.bdatPipe != nil {
		c.writeResponse(502, EnhancedCode{5, 5, 1}, "MAIL not allowed during message transfer")
		return
	}
	// RFC 5321 section 4.1.1.2: MAIL is only permitted when there is no
	// transaction in progress; a nested MAIL gets 503, the client must
	// RSET (or finish the transaction) first.
	if c.fromReceived {
		c.writeResponse(503, EnhancedCode{5, 5, 1}, "Sender already specified")
		return
	}

	arg, ok := cutPrefixFold(arg, "FROM:")
	if !ok {
		c.writeResponse(501, EnhancedCode{5, 5, 2}, "Was expecting MAIL arg syntax of FROM:<address>")
		return
	}

	p := parser{s: strings.TrimSpace(arg)}
	from, err := p.parseReversePath()
	if err != nil {
		c.writeResponse(501, EnhancedCode{5, 5, 2}, "Was expecting MAIL arg syntax of FROM:<address>")
		return
	}
	args, err := parseArgs(p.s)
	if err != nil {
		c.writeResponse(501, EnhancedCode{5, 5, 4}, "Unable to parse MAIL ESMTP parameters")
		return
	}

	opts := &MailOptions{}

	c.binarymime = false
	// This is where the Conn may put BODY=8BITMIME, but we already
	// read the DATA as bytes, so it does not effect our processing.
	for key, value := range args {
		switch key {
		case "SIZE":
			size, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				c.writeResponse(501, EnhancedCode{5, 5, 4}, "Unable to parse SIZE as an integer")
				return
			}

			if c.server.MaxMessageBytes > 0 && int64(size) > c.server.MaxMessageBytes {
				c.writeResponse(552, EnhancedCode{5, 3, 4}, "Max message size exceeded")
				return
			}

			opts.Size = int64(size)
		case "SMTPUTF8":
			if !c.server.EnableSMTPUTF8 {
				c.writeResponse(504, EnhancedCode{5, 5, 4}, "SMTPUTF8 is not implemented")
				return
			}
			opts.UTF8 = true
		case "REQUIRETLS":
			if !c.server.EnableREQUIRETLS {
				c.writeResponse(504, EnhancedCode{5, 5, 4}, "REQUIRETLS is not implemented")
				return
			}
			opts.RequireTLS = true
		case "BODY":
			value = strings.ToUpper(value)
			switch BodyType(value) {
			case BodyBinaryMIME:
				if !c.server.EnableBINARYMIME {
					c.writeResponse(504, EnhancedCode{5, 5, 4}, "BINARYMIME is not implemented")
					return
				}
				c.binarymime = true
			case Body7Bit, Body8BitMIME:
				// This space is intentionally left blank
			default:
				c.writeResponse(501, EnhancedCode{5, 5, 4}, "Unknown BODY value")
				return
			}
			opts.Body = BodyType(value)
		case "RET":
			if !c.server.EnableDSN {
				c.writeResponse(504, EnhancedCode{5, 5, 4}, "RET is not implemented")
				return
			}
			value = strings.ToUpper(value)
			switch DSNReturn(value) {
			case DSNReturnFull, DSNReturnHeaders:
				// This space is intentionally left blank
			default:
				c.writeResponse(501, EnhancedCode{5, 5, 4}, "Unknown RET value")
				return
			}
			opts.Return = DSNReturn(value)
		case "ENVID":
			if !c.server.EnableDSN {
				c.writeResponse(504, EnhancedCode{5, 5, 4}, "ENVID is not implemented")
				return
			}
			value, err := decodeXtext(value)
			if err != nil || value == "" || !isPrintableASCII(value) {
				c.writeResponse(501, EnhancedCode{5, 5, 4}, "Malformed ENVID parameter value")
				return
			}
			opts.EnvelopeID = value
		case "AUTH":
			value, err := decodeXtext(value)
			if err != nil || value == "" {
				c.writeResponse(501, EnhancedCode{5, 5, 4}, "Malformed AUTH parameter value")
				return
			}
			if value == "<>" {
				value = ""
			} else {
				p := parser{s: value}
				value, err = p.parseMailbox()
				if err != nil || p.s != "" {
					c.writeResponse(501, EnhancedCode{5, 5, 4}, "Malformed AUTH parameter mailbox")
					return
				}
			}
			opts.Auth = &value
		default:
			c.writeResponse(500, EnhancedCode{5, 5, 4}, "Unknown MAIL FROM argument")
			return
		}
	}

	err = c.withCommandContext(func(ctx context.Context) error {
		return c.Session().Mail(ctx, from, opts)
	})
	if err != nil {
		c.writeError(451, EnhancedCode{4, 0, 0}, err)
		return
	}

	c.writeResponse(250, EnhancedCode{2, 0, 0}, fmt.Sprintf("Roger, accepting mail from <%v>", from))
	c.fromReceived = true
}

// This regexp matches 'hexchar' token defined in
// https://tools.ietf.org/html/rfc4954#section-8 however it is intentionally
// relaxed by requiring only '+' to be present.  It allows us to detect
// malformed values such as +A or +HH and report them appropriately.
var hexcharRe = regexp.MustCompile(`\+[0-9A-F]?[0-9A-F]?`)

func decodeXtext(val string) (string, error) {
	if !strings.Contains(val, "+") {
		return val, nil
	}

	var replaceErr error
	decoded := hexcharRe.ReplaceAllStringFunc(val, func(match string) string {
		if len(match) != 3 {
			replaceErr = errors.New("incomplete hexchar")
			return ""
		}
		char, err := strconv.ParseInt(match, 16, 8)
		if err != nil {
			replaceErr = err
			return ""
		}

		return string(rune(char))
	})
	if replaceErr != nil {
		return "", replaceErr
	}

	return decoded, nil
}

// This regexp matches 'EmbeddedUnicodeChar' token defined in
// https://datatracker.ietf.org/doc/html/rfc6533.html#section-3
// however it is intentionally relaxed by requiring only '\x{HEX}' to be
// present.  It also matches disallowed characters in QCHAR and QUCHAR defined
// in above.
// So it allows us to detect malformed values and report them appropriately.
var eUOrDCharRe = regexp.MustCompile(`\\x[{][0-9A-F]+[}]|[[:cntrl:] \\+=]`)

// Decodes the utf-8-addr-xtext or the utf-8-addr-unitext form.
func decodeUTF8AddrXtext(val string) (string, error) {
	var replaceErr error
	decoded := eUOrDCharRe.ReplaceAllStringFunc(val, func(match string) string {
		if len(match) == 1 {
			replaceErr = errors.New("disallowed character:" + match)
			return ""
		}

		hexpoint := match[3 : len(match)-1]
		char, err := strconv.ParseUint(hexpoint, 16, 21)
		if err != nil {
			replaceErr = err
			return ""
		}
		switch len(hexpoint) {
		case 2:
			switch {
			// all xtext-specials
			case 0x01 <= char && char <= 0x09 ||
				0x11 <= char && char <= 0x19 ||
				char == 0x10 || char == 0x20 ||
				char == 0x2B || char == 0x3D || char == 0x7F:
			// 2-digit forms
			case char == 0x5C || 0x80 <= char && char <= 0xFF:
				// This space is intentionally left blank
			default:
				replaceErr = errors.New("illegal hexpoint:" + hexpoint)
				return ""
			}
		// 3-digit forms
		case 3:
			switch {
			case 0x100 <= char && char <= 0xFFF:
				// This space is intentionally left blank
			default:
				replaceErr = errors.New("illegal hexpoint:" + hexpoint)
				return ""
			}
		// 4-digit forms excluding surrogate
		case 4:
			switch {
			case 0x1000 <= char && char <= 0xD7FF:
			case 0xE000 <= char && char <= 0xFFFF:
				// This space is intentionally left blank
			default:
				replaceErr = errors.New("illegal hexpoint:" + hexpoint)
				return ""
			}
		// 5-digit forms
		case 5:
			switch {
			case 0x1_0000 <= char && char <= 0xF_FFFF:
				// This space is intentionally left blank
			default:
				replaceErr = errors.New("illegal hexpoint:" + hexpoint)
				return ""
			}
		// 6-digit forms
		case 6:
			switch {
			case 0x10_0000 <= char && char <= 0x10_FFFF:
				// This space is intentionally left blank
			default:
				replaceErr = errors.New("illegal hexpoint:" + hexpoint)
				return ""
			}
		// the other invalid forms
		default:
			replaceErr = errors.New("illegal hexpoint:" + hexpoint)
			return ""
		}

		return string(rune(char))
	})
	if replaceErr != nil {
		return "", replaceErr
	}

	return decoded, nil
}

func decodeTypedAddress(val string) (DSNAddressType, string, error) {
	tv := strings.SplitN(val, ";", 2)
	if len(tv) != 2 || tv[0] == "" || tv[1] == "" {
		return "", "", errors.New("bad address")
	}
	aType, aAddr := strings.ToUpper(tv[0]), tv[1]

	var err error
	switch DSNAddressType(aType) {
	case DSNAddressTypeRFC822:
		aAddr, err = decodeXtext(aAddr)
		if err == nil && !isPrintableASCII(aAddr) {
			err = errors.New("illegal address:" + aAddr)
		}
	case DSNAddressTypeUTF8:
		aAddr, err = decodeUTF8AddrXtext(aAddr)
	default:
		err = errors.New("unknown address type:" + aType)
	}
	if err != nil {
		return "", "", err
	}

	return DSNAddressType(aType), aAddr, nil
}

func encodeXtext(raw string) string {
	var out strings.Builder
	out.Grow(len(raw))

	for _, ch := range raw {
		switch {
		case ch >= '!' && ch <= '~' && ch != '+' && ch != '=':
			// printable non-space US-ASCII except '+' and '='
			out.WriteRune(ch)
		default:
			out.WriteRune('+')
			out.WriteString(strings.ToUpper(strconv.FormatInt(int64(ch), 16)))
		}
	}
	return out.String()
}

// Encodes raw string to the utf-8-addr-xtext form in RFC 6533.
func encodeUTF8AddrXtext(raw string) string {
	var out strings.Builder
	out.Grow(len(raw))

	for _, ch := range raw {
		switch {
		case ch >= '!' && ch <= '~' && ch != '+' && ch != '=':
			// printable non-space US-ASCII except '+' and '='
			out.WriteRune(ch)
		default:
			out.WriteRune('\\')
			out.WriteRune('x')
			out.WriteRune('{')
			out.WriteString(strings.ToUpper(strconv.FormatInt(int64(ch), 16)))
			out.WriteRune('}')
		}
	}
	return out.String()
}

// Encodes raw string to the utf-8-addr-unitext form in RFC 6533.
func encodeUTF8AddrUnitext(raw string) string {
	var out strings.Builder
	out.Grow(len(raw))

	for _, ch := range raw {
		switch {
		case ch >= '!' && ch <= '~' && ch != '+' && ch != '=':
			// printable non-space US-ASCII except '+' and '='
			out.WriteRune(ch)
		case ch <= '\x7F':
			// other ASCII: CTLs, space and specials
			out.WriteRune('\\')
			out.WriteRune('x')
			out.WriteRune('{')
			out.WriteString(strings.ToUpper(strconv.FormatInt(int64(ch), 16)))
			out.WriteRune('}')
		default:
			// UTF-8 non-ASCII
			out.WriteRune(ch)
		}
	}
	return out.String()
}

func isPrintableASCII(val string) bool {
	for _, ch := range val {
		if ch < ' ' || '~' < ch {
			return false
		}
	}
	return true
}

// MAIL state -> waiting for RCPTs followed by DATA
func (c *Conn) handleRcpt(arg string) {
	if !c.fromReceived {
		c.writeResponse(502, EnhancedCode{5, 5, 1}, "Missing MAIL FROM command.")
		return
	}
	if c.bdatPipe != nil {
		c.writeResponse(502, EnhancedCode{5, 5, 1}, "RCPT not allowed during message transfer")
		return
	}

	arg, ok := cutPrefixFold(arg, "TO:")
	if !ok {
		c.writeResponse(501, EnhancedCode{5, 5, 2}, "Was expecting RCPT arg syntax of TO:<address>")
		return
	}

	p := parser{s: strings.TrimSpace(arg)}
	recipient, err := p.parseForwardPath()
	if err != nil {
		c.writeResponse(501, EnhancedCode{5, 1, 3}, "Was expecting RCPT arg syntax of TO:<address>")
		return
	}

	if c.server.MaxRecipients > 0 && len(c.recipients) >= c.server.MaxRecipients {
		c.writeResponse(452, EnhancedCode{4, 5, 3}, fmt.Sprintf("Maximum limit of %v recipients reached", c.server.MaxRecipients))
		return
	}

	args, err := parseArgs(p.s)
	if err != nil {
		c.writeResponse(501, EnhancedCode{5, 5, 4}, "Unable to parse RCPT ESMTP parameters")
		return
	}

	opts := &RcptOptions{}

	for key, value := range args {
		switch key {
		case "NOTIFY":
			if !c.server.EnableDSN {
				c.writeResponse(504, EnhancedCode{5, 5, 4}, "NOTIFY is not implemented")
				return
			}
			notify := []DSNNotify{}
			for _, val := range strings.Split(value, ",") {
				notify = append(notify, DSNNotify(strings.ToUpper(val)))
			}
			if err := checkNotifySet(notify); err != nil {
				c.writeResponse(501, EnhancedCode{5, 5, 4}, "Malformed NOTIFY parameter value")
				return
			}
			opts.Notify = notify
		case "ORCPT":
			if !c.server.EnableDSN {
				c.writeResponse(504, EnhancedCode{5, 5, 4}, "ORCPT is not implemented")
				return
			}
			aType, aAddr, err := decodeTypedAddress(value)
			if err != nil || aAddr == "" {
				c.writeResponse(501, EnhancedCode{5, 5, 4}, "Malformed ORCPT parameter value")
				return
			}
			opts.OriginalRecipientType = aType
			opts.OriginalRecipient = aAddr
		case "RRVS":
			if !c.server.EnableRRVS {
				c.writeResponse(504, EnhancedCode{5, 5, 4}, "RRVS is not implemented")
				return
			}
			value, _, _ = strings.Cut(value, ";") // discard the no-support action
			rrvsTime, err := time.Parse(time.RFC3339, value)
			if err != nil {
				c.writeResponse(501, EnhancedCode{5, 5, 4}, "Malformed RRVS parameter value")
				return
			}
			opts.RequireRecipientValidSince = rrvsTime
		case "BY":
			if !c.server.EnableDELIVERBY {
				c.writeResponse(504, EnhancedCode{5, 5, 4}, "DELIVERBY is not implemented")
				return
			}
			deliverBy := parseDeliverByArgument(value)
			if deliverBy == nil {
				c.writeResponse(501, EnhancedCode{5, 5, 4}, "Malformed BY parameter value")
				return
			}
			if c.server.MinimumDeliverByTime != 0 &&
				deliverBy.Mode == DeliverByReturn &&
				deliverBy.Time < c.server.MinimumDeliverByTime {
				c.writeResponse(501, EnhancedCode{5, 5, 4}, "BY parameter is below server minimum")
				return
			}
			opts.DeliverBy = deliverBy
		case "MT-PRIORITY":
			if !c.server.EnableMTPRIORITY {
				c.writeResponse(504, EnhancedCode{5, 5, 4}, "MT-PRIORITY is not implemented")
				return
			}
			mtPriority, err := strconv.Atoi(value)
			if err != nil {
				c.writeResponse(501, EnhancedCode{5, 5, 4}, "Malformed MT-PRIORITY parameter value")
				return
			}
			if mtPriority < -9 || mtPriority > 9 {
				c.writeResponse(501, EnhancedCode{5, 5, 4}, "MT-PRIORITY is outside valid range")
				return
			}
			opts.MTPriority = &mtPriority
		default:
			// Handle custom extensions (non-standard parameters)
			if !c.server.EnableRCPTExtensions {
				c.writeResponse(500, EnhancedCode{5, 5, 4}, "Unknown RCPT parameter")
				return
			}

			if opts.Extensions == nil {
				opts.Extensions = make(map[string]string)
			}

			// Special validation for XRCPTFORWARD
			if key == "XRCPTFORWARD" {
				if err := c.validateXRCPTFORWARD(value); err != nil {
					c.writeResponse(501, EnhancedCode{5, 5, 4}, fmt.Sprintf("Malformed XRCPTFORWARD parameter: %v", err))
					return
				}
			}

			opts.Extensions[key] = value
		}
	}

	err = c.withCommandContext(func(ctx context.Context) error {
		return c.Session().Rcpt(ctx, recipient, opts)
	})
	if err != nil {
		c.writeError(451, EnhancedCode{4, 0, 0}, err)
		return
	}
	c.recipients = append(c.recipients, recipient)
	c.writeResponse(250, EnhancedCode{2, 0, 0}, fmt.Sprintf("I'll make sure <%v> gets this", recipient))
}

func checkNotifySet(values []DSNNotify) error {
	if len(values) == 0 {
		return errors.New("Malformed NOTIFY parameter value")
	}

	seen := map[DSNNotify]struct{}{}
	for _, val := range values {
		switch val {
		case DSNNotifyNever, DSNNotifyDelayed, DSNNotifyFailure, DSNNotifySuccess:
			if _, ok := seen[val]; ok {
				return errors.New("Malformed NOTIFY parameter value")
			}
		default:
			return errors.New("Malformed NOTIFY parameter value")
		}
		seen[val] = struct{}{}
	}
	if _, ok := seen[DSNNotifyNever]; ok && len(seen) > 1 {
		return errors.New("Malformed NOTIFY parameter value")
	}

	return nil
}

func (c *Conn) handleAuth(arg string) {
	if c.helo == "" {
		c.writeResponse(502, EnhancedCode{5, 5, 1}, "Please introduce yourself first.")
		return
	}
	if c.didAuth {
		c.writeResponse(503, EnhancedCode{5, 5, 1}, "Already authenticated")
		return
	}
	if c.fromReceived {
		c.writeResponse(503, EnhancedCode{5, 5, 1}, "Error: AUTH not permitted during mail transaction")
		return
	}

	parts := strings.Fields(arg)
	if len(parts) == 0 {
		c.writeResponse(501, EnhancedCode{5, 5, 4}, "Missing parameter")
		return
	}
	if len(parts) > 2 {
		c.writeResponse(501, EnhancedCode{5, 5, 4}, "Syntax error in parameters or arguments")
		return
	}

	if !c.authAllowed() {
		c.writeResponse(538, EnhancedCode{5, 7, 11}, "Encryption required for requested authentication mechanism")
		return
	}

	mechanism := strings.ToUpper(parts[0])

	// Parse client initial response if there is one
	var ir []byte
	if len(parts) > 1 {
		var err error
		ir, err = decodeSASLResponse(parts[1])
		if err != nil {
			c.authFailed(501, EnhancedCode{5, 5, 2}, errors.New("Invalid base64 data"))
			return
		}
	}

	sasl, err := c.auth(mechanism)
	if err != nil {
		c.authFailed(454, EnhancedCode{4, 7, 0}, err)
		return
	}

	response := ir
	for {
		challenge, done, err := sasl.Next(response)
		if err != nil {
			c.authFailed(454, EnhancedCode{4, 7, 0}, err)
			return
		}

		if done {
			break
		}

		encoded := ""
		if len(challenge) > 0 {
			encoded = base64.StdEncoding.EncodeToString(challenge)
		}
		c.writeResponse(334, NoEnhancedCode, encoded)

		encoded, err = c.readLine()
		if err != nil {
			// The SASL exchange cannot continue: report the read failure the
			// same way the serve loop would and drop the connection.
			// Returning silently would desync the session — the client's
			// next line, meant as a SASL response, would be parsed as an
			// SMTP command.
			c.readError(err)
			c.Close()
			return
		}

		if encoded == "*" {
			// https://tools.ietf.org/html/rfc4954#page-4
			c.writeResponse(501, EnhancedCode{5, 0, 0}, "Negotiation cancelled")
			return
		}

		response, err = decodeSASLResponse(encoded)
		if err != nil {
			c.authFailed(501, EnhancedCode{5, 5, 2}, errors.New("Invalid base64 data"))
			return
		}
	}

	c.writeResponse(235, EnhancedCode{2, 0, 0}, "Authentication succeeded")
	c.didAuth = true
}

func decodeSASLResponse(s string) ([]byte, error) {
	if s == "=" {
		return []byte{}, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func (c *Conn) authMechanisms() []string {
	if authSession, ok := c.Session().(AuthSession); ok {
		return authSession.AuthMechanisms()
	}
	return nil
}

func (c *Conn) auth(mech string) (sasl.Server, error) {
	if authSession, ok := c.Session().(AuthSession); ok {
		return authSession.Auth(mech)
	}
	return nil, ErrAuthUnknownMechanism
}

// logStartTLSError logs a STARTTLS-related error to the configured ErrorLog,
// falling back to the standard logger when none is set (a Server constructed
// without NewServer may leave ErrorLog nil).
func (c *Conn) logStartTLSError(err error) {
	if c.server.ErrorLog != nil {
		c.server.ErrorLog.Printf("STARTTLS error from %v: %v", c.conn.RemoteAddr(), err)
	} else {
		log.Printf("STARTTLS error from %v: %v", c.conn.RemoteAddr(), err)
	}
}

func (c *Conn) handleStartTLS() {
	if _, isTLS := c.TLSConnectionState(); isTLS {
		c.writeResponse(502, EnhancedCode{5, 5, 1}, "Already running in TLS")
		return
	}

	if c.server.TLSConfig == nil {
		c.writeResponse(502, EnhancedCode{5, 5, 1}, "TLS not supported")
		return
	}

	c.writeResponse(220, EnhancedCode{2, 0, 0}, "Ready to start TLS")

	// Defense against the STARTTLS plaintext command injection attack: any
	// bytes buffered past the STARTTLS line were received before the TLS
	// handshake and must never be interpreted as if they had arrived inside
	// the encrypted channel. Their presence indicates an injection attempt, so
	// abort the connection rather than silently discarding them. (The reader
	// is rebuilt by init() below, which already drops buffered bytes, but this
	// makes the guarantee explicit and independent of that side effect.)
	if n := c.text.R.Buffered(); n > 0 {
		c.logStartTLSError(fmt.Errorf("%d buffered bytes before TLS handshake, possible plaintext command injection", n))
		c.Close()
		// Closing the socket is not enough: the buffered plaintext still lives
		// in c.text's reader and the serve loop would otherwise read and
		// dispatch it as commands. Rebuild the reader over the now-closed
		// connection so the buffered bytes are discarded and the next read
		// fails, ending the serve loop.
		c.init()
		return
	}

	// Apply fresh deadlines for the handshake so a client that stalls
	// mid-handshake cannot pin this goroutine indefinitely. This mirrors the
	// implicit-TLS path in Server.handleConn; without it the STARTTLS handshake
	// would run under whatever stale deadline the previous read/write left, or
	// none at all when timeouts are disabled.
	if d := c.server.ReadTimeout; d != 0 {
		c.conn.SetReadDeadline(time.Now().Add(d))
	}
	if d := c.server.WriteTimeout; d != 0 {
		c.conn.SetWriteDeadline(time.Now().Add(d))
	}

	// Upgrade to TLS
	tlsConn := tls.Server(c.conn, c.server.TLSConfig)

	if err := tlsConn.Handshake(); err != nil {
		c.logStartTLSError(fmt.Errorf("handshake failed: %w", err))
		// The TLS layer has already consumed bytes from the connection and the
		// peer expects TLS records, so the plaintext stream is desynchronized.
		// Close rather than attempting to continue or to write a plaintext
		// response the peer cannot interpret.
		c.Close()
		return
	}

	// Guard the connection swap with c.locker: Conn.Close() reads c.conn under
	// the same lock and can run on a different goroutine during
	// Server.Close/Shutdown. Without this, the unsynchronized write to c.conn
	// races that locked read (a torn read of the interface value could crash).
	c.locker.Lock()
	c.conn = tlsConn
	c.locker.Unlock()
	c.init()

	// Reset all state and close the previous Session.
	// This is different from just calling reset() since we want the Backend to
	// be able to see the information about TLS connection in the
	// ConnectionState object passed to it.
	if session := c.Session(); session != nil {
		c.logoutSession(session)
		c.setSession(nil)
	}
	c.helo = ""
	c.setGreeting("")
	c.didAuth = false
	// RFC 3207 section 4.2: the server MUST discard any knowledge obtained from
	// the client which was not obtained from the TLS negotiation itself.
	c.xclientData = nil
	c.reset()
}

// DATA
func (c *Conn) handleData(arg string) {
	if arg != "" {
		c.writeResponse(501, EnhancedCode{5, 5, 4}, "DATA command should not have any arguments")
		return
	}
	if c.bdatPipe != nil {
		c.writeResponse(502, EnhancedCode{5, 5, 1}, "DATA not allowed during message transfer")
		return
	}
	if c.binarymime {
		c.writeResponse(502, EnhancedCode{5, 5, 1}, "DATA not allowed for BINARYMIME messages")
		return
	}

	if !c.fromReceived || len(c.recipients) == 0 {
		c.writeResponse(502, EnhancedCode{5, 5, 1}, "Missing RCPT TO command.")
		return
	}

	// We have recipients, go to accept data
	c.writeResponse(354, NoEnhancedCode, "Go ahead. End your data with <CR><LF>.<CR><LF>")

	defer c.reset()

	if c.server.LMTP {
		c.handleDataLMTP()
		return
	}

	r := newDataReader(c)
	code, enhancedCode, msg := dataErrorToStatus(c.withCommandContext(func(ctx context.Context) error {
		return c.Session().Data(ctx, r)
	}))
	r.limited = false
	io.Copy(io.Discard, r) // Make sure all the data has been consumed
	c.writeResponse(code, enhancedCode, msg)
}

func (c *Conn) handleBdat(arg string) {
	args := strings.Fields(arg)
	if len(args) == 0 {
		c.writeResponse(501, EnhancedCode{5, 5, 4}, "Missing chunk size argument")
		return
	}
	if len(args) > 2 {
		c.writeResponse(501, EnhancedCode{5, 5, 4}, "Too many arguments")
		return
	}

	if !c.fromReceived || len(c.recipients) == 0 {
		c.writeResponse(502, EnhancedCode{5, 5, 1}, "Missing RCPT TO command.")
		return
	}

	last := false
	if len(args) == 2 {
		if !strings.EqualFold(args[1], "LAST") {
			c.writeResponse(501, EnhancedCode{5, 5, 4}, "Unknown BDAT argument")
			return
		}
		last = true
	}

	// ParseUint instead of Atoi so we will not accept negative values.
	size, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		c.writeResponse(501, EnhancedCode{5, 5, 4}, "Malformed size argument")
		return
	}

	if c.server.MaxMessageBytes != 0 && c.bytesReceived+int64(size) > c.server.MaxMessageBytes {
		c.writeResponse(552, EnhancedCode{5, 3, 4}, "Max message size exceeded")

		// Discard chunk itself without passing it to backend.
		io.Copy(io.Discard, io.LimitReader(c.text.R, int64(size)))

		c.reset()
		return
	}

	if c.bdatStatus == nil && c.server.LMTP {
		c.bdatStatus = c.createStatusCollector()
	}

	if c.bdatPipe == nil {
		var r *io.PipeReader
		r, c.bdatPipe = io.Pipe()

		c.dataResult = make(chan error, 1)

		// The data goroutine runs concurrently with the serve loop, which can
		// abort the transfer (RSET, Close) and clear connection state under
		// c.locker; give the goroutine stable copies instead of Conn fields.
		recipients := append([]string(nil), c.recipients...)
		bdatStatus := c.bdatStatus

		// Unlike DATA, BDAT returns to the command loop between chunks, so
		// the transaction can be aborted while the backend call is still in
		// flight. A backend blocked in upstream I/O never observes the pipe's
		// ErrDataReset; register the cancel on the Conn so reset() and
		// Close() can deliver the abort through the context.
		dataCtx, dataCancel := context.WithCancel(c.Context())
		c.locker.Lock()
		c.bdatCtxCancel = dataCancel
		c.locker.Unlock()

		go func() {
			defer dataCancel()
			defer func() {
				if err := recover(); err != nil {
					c.handlePanic(err, bdatStatus)

					c.dataResult <- errPanic
					r.CloseWithError(errPanic)
				}
			}()

			var err error
			if !c.server.LMTP {
				err = c.Session().Data(dataCtx, r)
			} else {
				lmtpSession, ok := c.Session().(LMTPSession)
				if !ok {
					err = c.Session().Data(dataCtx, r)
					for _, rcpt := range recipients {
						bdatStatus.SetStatus(rcpt, err)
					}
				} else {
					err = lmtpSession.LMTPData(dataCtx, r, bdatStatus)
				}
			}

			c.dataResult <- err
			r.CloseWithError(err)
		}()
	}

	chunk := io.LimitReader(c.text.R, int64(size))
	_, err = io.Copy(c.bdatPipe, chunk)
	if err != nil {
		// Backend might return an error early using CloseWithError without consuming
		// the whole chunk.
		io.Copy(io.Discard, chunk)

		c.writeResponse(dataErrorToStatus(err))

		if err == errPanic {
			c.Close()
		}

		c.reset()
		return
	}

	c.bytesReceived += int64(size)

	if last {
		c.bdatPipe.Close()

		err := <-c.dataResult

		if c.server.LMTP {
			c.bdatStatus.fillRemaining(err)
			for i, rcpt := range c.recipients {
				code, enchCode, msg := dataErrorToStatus(<-c.bdatStatus.status[i])
				c.writeResponse(code, enchCode, "<"+rcpt+"> "+msg)
			}
		} else {
			c.writeResponse(dataErrorToStatus(err))
		}

		if err == errPanic {
			c.Close()
			return
		}

		c.reset()
	} else {
		c.writeResponse(250, EnhancedCode{2, 0, 0}, "Continue")
	}
}

// ErrDataReset is returned by Reader pased to Data function if client does not
// send another BDAT command and instead closes connection or issues RSET command.
var ErrDataReset = errors.New("smtp: message transmission aborted")

var errPanic = &SMTPError{
	Code:         421,
	EnhancedCode: EnhancedCode{4, 0, 0},
	Message:      "Internal server error",
}

func (c *Conn) handlePanic(err interface{}, status *statusCollector) {
	if status != nil {
		status.fillRemaining(errPanic)
	}

	stack := debug.Stack()
	c.server.ErrorLog.Printf("panic serving %v: %v\n%s", c.conn.RemoteAddr(), err, stack)
}

func (c *Conn) createStatusCollector() *statusCollector {
	rcptCounts := make(map[string]int, len(c.recipients))

	status := &statusCollector{
		statusMap: make(map[string]chan error, len(c.recipients)),
		status:    make([]chan error, 0, len(c.recipients)),
	}
	for _, rcpt := range c.recipients {
		rcptCounts[rcpt]++
	}
	// Create channels with buffer sizes necessary to fit all
	// statuses for a single recipient to avoid deadlocks.
	for rcpt, count := range rcptCounts {
		status.statusMap[rcpt] = make(chan error, count)
	}
	for _, rcpt := range c.recipients {
		status.status = append(status.status, status.statusMap[rcpt])
	}

	return status
}

type statusCollector struct {
	// Contains map from recipient to list of channels that are used for that
	// recipient.
	statusMap map[string]chan error

	// Contains channels from statusMap, in the same
	// order as Conn.recipients.
	status []chan error
}

// fillRemaining sets status for all recipients SetStatus was not called for before.
func (s *statusCollector) fillRemaining(err error) {
	// Amount of times certain recipient was specified is indicated by the channel
	// buffer size, so once we fill it, we can be confident that we sent
	// at least as much statuses as needed. Extra statuses will be ignored anyway.
chLoop:
	for _, ch := range s.statusMap {
		for {
			select {
			case ch <- err:
			default:
				continue chLoop
			}
		}
	}
}

func (s *statusCollector) SetStatus(rcptTo string, err error) {
	ch := s.statusMap[rcptTo]
	if ch == nil {
		panic("SetStatus is called for recipient that was not specified before")
	}

	select {
	case ch <- err:
	default:
		// There enough buffer space to fit all statuses at once, if this is
		// not the case - backend is doing something wrong.
		panic("SetStatus is called more times than particular recipient was specified")
	}
}

func (c *Conn) handleDataLMTP() {
	r := newDataReader(c)
	status := c.createStatusCollector()

	done := make(chan bool, 1)

	lmtpSession, ok := c.Session().(LMTPSession)
	if !ok {
		// Fallback to using a single status for all recipients.
		err := c.withCommandContext(func(ctx context.Context) error {
			return c.Session().Data(ctx, r)
		})
		io.Copy(io.Discard, r) // Make sure all the data has been consumed
		for _, rcpt := range c.recipients {
			status.SetStatus(rcpt, err)
		}
		done <- true
	} else {
		go func() {
			defer func() {
				if err := recover(); err != nil {
					status.fillRemaining(&SMTPError{
						Code:         421,
						EnhancedCode: EnhancedCode{4, 0, 0},
						Message:      "Internal server error",
					})

					stack := debug.Stack()
					c.server.ErrorLog.Printf("panic serving %v: %v\n%s", c.conn.RemoteAddr(), err, stack)
					done <- false
				}
			}()

			status.fillRemaining(c.withCommandContext(func(ctx context.Context) error {
				return lmtpSession.LMTPData(ctx, r, status)
			}))
			io.Copy(io.Discard, r) // Make sure all the data has been consumed
			done <- true
		}()
	}

	for i, rcpt := range c.recipients {
		code, enchCode, msg := dataErrorToStatus(<-status.status[i])
		c.writeResponse(code, enchCode, "<"+rcpt+"> "+msg)
	}

	// If done gets false, the panic occurred in LMTPData and the connection
	// should be closed.
	if !<-done {
		c.Close()
	}
}

func dataErrorToStatus(err error) (code int, enchCode EnhancedCode, msg string) {
	if err != nil {
		if smtperr, ok := err.(*SMTPError); ok {
			return smtperr.Code, smtperr.EnhancedCode, smtperr.Message
		} else {
			return 554, EnhancedCode{5, 0, 0}, "Error: transaction failed: " + err.Error()
		}
	}

	return 250, EnhancedCode{2, 0, 0}, "OK: queued"
}

func (c *Conn) Reject() {
	c.writeResponse(421, EnhancedCode{4, 4, 5}, "Too busy. Try again later.")
	c.Close()
}

func (c *Conn) greet() {
	protocol := "ESMTP"
	if c.server.LMTP {
		protocol = "LMTP"
	}
	c.writeResponse(220, NoEnhancedCode, fmt.Sprintf("%v %s Service Ready", c.server.Domain, protocol))
}

func (c *Conn) writeResponse(code int, enhCode EnhancedCode, text ...string) {
	// Once a response write has failed the connection is done for; don't
	// bother the socket with further writes, the serve loop is about to
	// tear the connection down.
	if c.writeFailure != nil {
		return
	}

	if c.server.WriteTimeout != 0 {
		c.conn.SetWriteDeadline(time.Now().Add(c.server.WriteTimeout))
	}

	// All responses must include an enhanced code, if it is missing - use
	// a generic code X.0.0.
	if enhCode == EnhancedCodeNotSet {
		cat := code / 100
		switch cat {
		case 2, 4, 5:
			enhCode = EnhancedCode{cat, 0, 0}
		default:
			enhCode = NoEnhancedCode
		}
	}

	// transform each single line with \n, into separate lines
	text = strings.Split(strings.Join(text, "\n"), "\n")

	// Strip CR from every line: backend-provided text containing \r\n would
	// otherwise leave a trailing \r after the split above (yielding \r\r\n on
	// the wire), and a bare CR inside a reply line is invalid in SMTP. The
	// wire-format CRLF is appended by PrintfLine below.
	for i := range text {
		text[i] = strings.ReplaceAll(text[i], "\r", "")
	}

	lastLineIndex := len(text) - 1
	for i := 0; i < lastLineIndex; i++ {
		if err := c.text.PrintfLine("%d-%v", code, text[i]); err != nil {
			c.writeFailure = err
			return
		}
	}
	var err error
	if enhCode == NoEnhancedCode {
		err = c.text.PrintfLine("%d %v", code, text[lastLineIndex])
	} else {
		err = c.text.PrintfLine("%d %v.%v.%v %v", code, enhCode[0], enhCode[1], enhCode[2], text[lastLineIndex])
	}
	if err != nil {
		c.writeFailure = err
	}
}

func (c *Conn) writeError(code int, enhCode EnhancedCode, err error) {
	if smtpErr, ok := err.(*SMTPError); ok {
		c.writeResponse(smtpErr.Code, smtpErr.EnhancedCode, smtpErr.Message)
	} else {
		c.writeResponse(code, enhCode, err.Error())
	}
}

// Reads a line of input, enforcing Server.MaxLineLength on the line itself
// (excluding CRLF). Bytes buffered behind the line — such as a pipelined BDAT
// chunk following its command — do not count toward the limit.
func (c *Conn) readLine() (string, error) {
	deadline, configured := c.getSessionDeadline()
	if c.server.ReadTimeout != 0 {
		idleDeadline := time.Now().Add(c.server.ReadTimeout)
		if deadline.IsZero() || idleDeadline.Before(deadline) {
			deadline = idleDeadline
		}
	}
	if configured || !deadline.IsZero() {
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return "", err
		}
	}

	var line []byte
	for {
		l, more, err := c.text.R.ReadLine()
		if err != nil {
			return "", err
		}
		line = append(line, l...)

		// Check while the line accumulates, not just at the end, so memory
		// stays bounded by MaxLineLength plus one buffer fill even when the
		// client never sends a newline.
		if c.server.MaxLineLength > 0 && len(line) > c.server.MaxLineLength {
			return "", ErrTooLongLine
		}
		if !more {
			return string(line), nil
		}
	}
}

// validateXRCPTFORWARD validates an XRCPTFORWARD parameter value according to Dovecot specification
func (c *Conn) validateXRCPTFORWARD(value string) error {
	// XRCPTFORWARD must be base64 encoded but can encode empty content
	if value == "" {
		return errors.New("XRCPTFORWARD value cannot be empty")
	}

	// Check if it's valid base64
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("invalid base64 encoding: %v", err)
	}

	// Check size limit (~900 bytes per Dovecot spec)
	if len(decoded) > 900 {
		return fmt.Errorf("XRCPTFORWARD data too large: %d bytes (max 900)", len(decoded))
	}

	// Validate that it contains tab-separated key=value pairs (empty content is allowed)
	decodedStr := string(decoded)
	if err := c.validateXRCPTFORWARDContent(decodedStr); err != nil {
		return fmt.Errorf("invalid content: %v", err)
	}

	return nil
}

// validateXRCPTFORWARDContent validates the decoded XRCPTFORWARD content
func (c *Conn) validateXRCPTFORWARDContent(content string) error {
	// Allow empty content
	if content == "" {
		return nil
	}

	// Content should be tab-separated key=value pairs
	// Split by literal tabs first, then unescape individual pairs
	pairs := strings.Split(content, "\t")

	for _, pair := range pairs {
		if pair == "" {
			continue // Allow empty pairs
		}

		// Each pair should be key=value
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid key=value pair format: %s", pair)
		}

		// Key cannot be empty
		if parts[0] == "" {
			return errors.New("empty key in key=value pair")
		}
	}

	return nil
}

// unescapeXRCPTFORWARD handles Dovecot's escape sequences (\t, \n, \r, \\)
func unescapeXRCPTFORWARD(escaped string) string {
	// Order matters: handle \\ first to avoid double-processing
	result := strings.ReplaceAll(escaped, "\\\\", "\x00") // temporary placeholder
	result = strings.ReplaceAll(result, "\\t", "\t")
	result = strings.ReplaceAll(result, "\\n", "\n")
	result = strings.ReplaceAll(result, "\\r", "\r")
	result = strings.ReplaceAll(result, "\x00", "\\") // restore backslashes
	return result
}

// ParseXRCPTFORWARD parses XRCPTFORWARD data into key=value pairs
// This is a utility function that backends can use to parse the forwarded data
func ParseXRCPTFORWARD(value string) (map[string]string, error) {
	if value == "" {
		return nil, errors.New("XRCPTFORWARD value cannot be empty")
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding: %v", err)
	}

	content := string(decoded)

	// Split by literal tabs first (before unescaping)
	pairs := strings.Split(content, "\t")
	result := make(map[string]string)

	for _, pair := range pairs {
		if pair == "" {
			continue
		}

		// Split into key=value
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid key=value pair format: %s", pair)
		}
		if parts[0] == "" {
			return nil, errors.New("empty key in key=value pair")
		}

		key := parts[0]
		value := parts[1]

		// Unescape the value (not the key)
		result[key] = unescapeXRCPTFORWARD(value)
	}

	return result, nil
}

func (c *Conn) handleXCLIENT(arg string) {
	// XCLIENT can only be used before authentication
	if c.didAuth {
		c.writeResponse(503, EnhancedCode{5, 5, 1}, "XCLIENT not permitted after authentication")
		return
	}

	// XCLIENT can only be used before MAIL FROM
	if c.fromReceived {
		c.writeResponse(503, EnhancedCode{5, 5, 1}, "XCLIENT not permitted after MAIL FROM")
		return
	}

	// Check if XCLIENT is enabled
	if !c.server.EnableXCLIENT {
		c.writeResponse(502, EnhancedCode{5, 5, 1}, "XCLIENT command not implemented")
		return
	}

	// Check if connection is from trusted network
	if !c.isXCLIENTTrusted() {
		c.writeResponse(550, EnhancedCode{5, 7, 1}, "XCLIENT denied")
		return
	}

	// Parse XCLIENT attributes
	attrs, err := c.parseXCLIENTArgs(arg)
	if err != nil {
		c.writeResponse(501, EnhancedCode{5, 5, 4}, fmt.Sprintf("Invalid XCLIENT syntax: %v", err))
		return
	}

	// Validate attributes
	if err := c.validateXCLIENTAttrs(attrs); err != nil {
		c.writeResponse(501, EnhancedCode{5, 5, 4}, fmt.Sprintf("Invalid XCLIENT attributes: %v", err))
		return
	}

	// Initialize xclientData if not already done
	if c.xclientData == nil {
		c.xclientData = make(map[string]string)
	}

	// Store attributes
	for name, value := range attrs {
		c.xclientData[name] = value
	}

	// Call backend XCLIENT handler if implemented
	if xclientBackend, ok := c.Session().(XCLIENTBackend); ok {
		if err := xclientBackend.XCLIENT(c.Session(), attrs); err != nil {
			c.writeError(451, EnhancedCode{4, 0, 0}, err)
			return
		}
	}

	// Per XCLIENT spec, we must reset the session state and issue a new
	// greeting. This is similar to what we do for STARTTLS.
	if session := c.Session(); session != nil {
		c.logoutSession(session)
		c.setSession(nil)
	}
	c.helo = ""
	c.setGreeting("")
	c.didAuth = false
	c.reset()

	// And send a new greeting.
	c.greet()
}

func (c *Conn) isXCLIENTTrusted() bool {
	if len(c.server.XCLIENTTrustedNets) == 0 {
		return false
	}

	clientIP, _, err := net.SplitHostPort(c.conn.RemoteAddr().String())
	if err != nil {
		return false
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	for _, network := range c.server.XCLIENTTrustedNets {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

func (c *Conn) parseXCLIENTArgs(arg string) (map[string]string, error) {
	attrs := make(map[string]string)

	if arg == "" {
		return attrs, nil
	}

	fields := strings.Fields(arg)
	for _, field := range fields {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid attribute format: %s", field)
		}

		name := strings.ToUpper(parts[0])
		value := parts[1]

		attrs[name] = value
	}

	return attrs, nil
}

func (c *Conn) validateXCLIENTAttrs(attrs map[string]string) error {
	// List of valid XCLIENT attributes
	validAttrs := map[string]bool{
		"ADDR":  true,
		"PORT":  true,
		"PROTO": true,
		"HELO":  true,
		"LOGIN": true,
		"NAME":  true,
	}

	for name, value := range attrs {
		if !validAttrs[name] {
			return fmt.Errorf("unknown attribute: %s", name)
		}

		// Validate special values
		if value == "[UNAVAILABLE]" || value == "[TEMPUNAVAIL]" {
			continue
		}

		// Validate specific attributes
		switch name {
		case "ADDR":
			addrValue := value
			if strings.HasPrefix(strings.ToLower(addrValue), "ipv6:") {
				addrValue = addrValue[5:]
			}
			if net.ParseIP(addrValue) == nil {
				return fmt.Errorf("invalid IP address for ADDR: %s", value)
			}
		case "PORT":
			if port, err := strconv.Atoi(value); err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("invalid port number for PORT: %s", value)
			}
		case "PROTO":
			validProtos := map[string]bool{"SMTP": true, "ESMTP": true, "LMTP": true}
			if !validProtos[strings.ToUpper(value)] {
				return fmt.Errorf("invalid protocol for PROTO: %s", value)
			}
		case "HELO", "LOGIN", "NAME":
			if value == "" {
				return fmt.Errorf("empty value for %s", name)
			}
		}
	}

	return nil
}

// XCLIENTData returns the XCLIENT attributes provided by the client
func (c *Conn) XCLIENTData() map[string]string {
	c.locker.Lock()
	defer c.locker.Unlock()

	if c.xclientData == nil {
		return nil
	}

	// Return a copy to prevent modification
	result := make(map[string]string)
	for k, v := range c.xclientData {
		result[k] = v
	}
	return result
}

func (c *Conn) reset() {
	// Clear connection state under the lock, but call Session.Reset outside of
	// it, exactly as Conn.Close does for Logout: backends may call locked Conn
	// accessors (Conn, Session, TLSConnectionState, ...) from within Reset, and
	// c.locker is not reentrant, so holding it across the callback deadlocks
	// the connection goroutine for the rest of the connection's life. That hangs
	// every RSET and every message completion (handleData resets on return), and
	// the goroutine, socket and session are never released.
	c.locker.Lock()
	if c.bdatPipe != nil {
		c.bdatPipe.CloseWithError(ErrDataReset)
		c.bdatPipe = nil
	}
	if c.bdatCtxCancel != nil {
		// The pipe error only reaches a backend that is reading the message;
		// cancelling the command context aborts one blocked in upstream I/O.
		c.bdatCtxCancel()
		c.bdatCtxCancel = nil
	}
	c.bdatStatus = nil
	c.bytesReceived = 0
	c.fromReceived = false
	c.recipients = nil
	c.binarymime = false
	session := c.session
	c.locker.Unlock()

	if session != nil {
		c.resetSession(session)
	}
}
