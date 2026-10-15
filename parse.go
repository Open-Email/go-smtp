package smtp

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// cutPrefixFold is a version of strings.CutPrefix which is case-insensitive.
func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return "", false
	}
	return s[len(prefix):], true
}

func parseCmd(line string) (cmd string, arg string, err error) {
	line = strings.TrimRight(line, "\r\n")

	if len(line) == 0 {
		return "", "", nil
	}

	// Find the first space to separate command from arguments
	spaceIndex := strings.IndexByte(line, ' ')

	if spaceIndex == -1 {
		// No space found, entire line is the command
		if len(line) < 4 {
			return "", "", fmt.Errorf("command too short: %q", line)
		}
		return strings.ToUpper(line), "", nil
	}

	// Space found, split into command and arguments
	if spaceIndex < 4 {
		return "", "", fmt.Errorf("command too short: %q", line)
	}

	command := strings.ToUpper(line[:spaceIndex])
	arguments := strings.TrimSpace(line[spaceIndex+1:])

	return command, arguments, nil
}

// Takes the arguments proceeding a command and files them
// into a map[string]string after uppercasing each key.  Sample arg
// string:
//
//	" BODY=8BITMIME SIZE=1024 SMTPUTF8"
//
// The leading space is mandatory.
func parseArgs(s string) (map[string]string, error) {
	argMap := map[string]string{}
	for _, arg := range strings.Fields(s) {
		// Split on the first '=' only: parameter values may themselves
		// contain '=' (e.g. AUTH=dXNlcg== with base64 padding, RFC 4954,
		// or an ORCPT address).
		key, value, found := strings.Cut(arg, "=")
		if found {
			argMap[strings.ToUpper(key)] = value
		} else {
			argMap[strings.ToUpper(key)] = ""
		}
	}
	return argMap, nil
}

func parseHelloArgument(arg string) (string, error) {
	domain := arg
	if idx := strings.IndexRune(arg, ' '); idx >= 0 {
		domain = arg[:idx]
	}
	if domain == "" {
		return "", fmt.Errorf("invalid domain")
	}
	return domain, nil
}

// Parses the BY argument defined in RFC2852 section 4.
// Returns pointer to options or nil if invalid.
func parseDeliverByArgument(arg string) *DeliverByOptions {
	secondsStr, modeStr, ok := strings.Cut(arg, ";")
	if !ok {
		return nil
	}
	modeStr, traceValue := strings.CutSuffix(modeStr, "T")
	if modeStr != string(DeliverByNotify) && modeStr != string(DeliverByReturn) {
		return nil
	}
	modeValue := DeliverByMode(modeStr)
	secondsValue, err := strconv.Atoi(secondsStr)
	if err != nil || (modeValue == DeliverByReturn && secondsValue < 1) {
		return nil
	}
	return &DeliverByOptions{
		Time:  time.Duration(secondsValue) * time.Second,
		Mode:  modeValue,
		Trace: traceValue,
	}
}

// parser parses command arguments defined in RFC 5321 section 4.1.2.
type parser struct {
	s string
}

func (p *parser) peekByte() (byte, bool) {
	if len(p.s) == 0 {
		return 0, false
	}
	return p.s[0], true
}

func (p *parser) readByte() (byte, bool) {
	ch, ok := p.peekByte()
	if ok {
		p.s = p.s[1:]
	}
	return ch, ok
}

func (p *parser) acceptByte(ch byte) bool {
	got, ok := p.peekByte()
	if !ok || got != ch {
		return false
	}
	p.readByte()
	return true
}

func (p *parser) expectByte(ch byte) error {
	if !p.acceptByte(ch) {
		if len(p.s) == 0 {
			return fmt.Errorf("expected '%v', got EOF", string(ch))
		} else {
			return fmt.Errorf("expected '%v', got '%v'", string(ch), string(p.s[0]))
		}
	}
	return nil
}

func (p *parser) parseReversePath() (string, error) {
	if strings.HasPrefix(p.s, "<>") {
		p.s = strings.TrimPrefix(p.s, "<>")
		return "", nil
	}
	return p.parsePath()
}

func (p *parser) parseForwardPath() (string, error) {
	if rest, ok := cutPrefixFold(p.s, "<postmaster>"); ok {
		if rest == "" || rest[0] == ' ' || rest[0] == '\t' {
			mbox := p.s[1 : 1+len("postmaster")]
			p.s = rest
			return mbox, nil
		}
	}
	return p.parsePath()
}

func (p *parser) parsePath() (string, error) {
	hasBracket := p.acceptByte('<')
	if p.acceptByte('@') {
		i := strings.IndexByte(p.s, ':')
		if i < 0 {
			return "", fmt.Errorf("malformed a-d-l")
		}
		for j := 0; j < i; j++ {
			if p.s[j] <= 0x20 || p.s[j] == 0x7f {
				return "", fmt.Errorf("malformed a-d-l")
			}
		}
		p.s = p.s[i+1:]
	}
	mbox, err := p.parseMailbox()
	if err != nil {
		return "", fmt.Errorf("in mailbox: %v", err)
	}
	if hasBracket {
		if err := p.expectByte('>'); err != nil {
			return "", err
		}
	} else if strings.TrimSpace(p.s) != "" {
		// Preserve legacy bare mailbox compatibility only without parameters.
		// ESMTP parameters require the path's explicit closing delimiter.
		return "", fmt.Errorf("path with parameters must be enclosed in angle brackets")
	}
	return mbox, nil
}

func (p *parser) parseMailbox() (string, error) {
	localPart, err := p.parseLocalPart()
	if err != nil {
		return "", fmt.Errorf("in local-part: %v", err)
	} else if localPart == "" {
		return "", fmt.Errorf("local-part is empty")
	}

	if err := p.expectByte('@'); err != nil {
		return "", err
	}

	var sb strings.Builder
	sb.WriteString(localPart)
	sb.WriteByte('@')

	for {
		ch, ok := p.peekByte()
		if !ok {
			break
		}
		if ch == ' ' || ch == '\t' || ch == '>' {
			break
		}
		if ch < 0x20 || ch == 0x7f {
			return "", fmt.Errorf("malformed domain")
		}
		p.readByte()
		sb.WriteByte(ch)
	}

	if strings.HasSuffix(sb.String(), "@") {
		return "", fmt.Errorf("domain is empty")
	}

	return sb.String(), nil
}

func (p *parser) parseLocalPart() (string, error) {
	var sb strings.Builder

	if p.acceptByte('"') { // quoted-string
		for {
			ch, ok := p.readByte()
			switch ch {
			case '\\':
				ch, ok = p.readByte()
			case '"':
				return sb.String(), nil
			}
			if !ok || ch < 0x20 || ch == 0x7f {
				return "", fmt.Errorf("malformed quoted-string")
			}
			sb.WriteByte(ch)
		}
	} else { // dot-string
		for {
			ch, ok := p.peekByte()
			if !ok {
				break
			}
			switch ch {
			case '@', '>':
				goto done
			case '(', ')', '<', '[', ']', ':', ';', '\\', ',', '"', ' ', '\t':
				return "", fmt.Errorf("malformed dot-string")
			}
			if ch < 0x20 || ch == 0x7f {
				return "", fmt.Errorf("malformed dot-string")
			}
			p.readByte()
			sb.WriteByte(ch)
		}
	done:
		// Leading, trailing and consecutive dots are not a valid RFC 5321
		// Dot-string, but they are accepted on purpose, as Postfix does:
		// older Japanese carrier addresses (docomo, au/ezweb, SoftBank)
		// still use them in large numbers, and refusing them at MAIL FROM
		// bounces their mail (Open-Email/smtp-in#108). Every other refusal
		// above stands.
		return sb.String(), nil
	}
}
