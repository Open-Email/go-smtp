package smtp

import (
	"testing"
)

func TestParser(t *testing.T) {
	validReversePaths := []struct {
		raw, path, after string
	}{
		{"<>", "", ""},
		{"<root@nsa.gov>", "root@nsa.gov", ""},
		{"root@nsa.gov", "root@nsa.gov", ""},
		{"<root@nsa.gov> AUTH=asdf@example.org", "root@nsa.gov", " AUTH=asdf@example.org"},
		{`<"u..ser"@example.org>`, "u..ser@example.org", ""},
		{`<"user."@example.org>`, "user.@example.org", ""},
	}
	for _, tc := range validReversePaths {
		p := parser{tc.raw}
		path, err := p.parseReversePath()
		if err != nil {
			t.Errorf("parser.parseReversePath(%q) = %v", tc.raw, err)
		} else if path != tc.path {
			t.Errorf("parser.parseReversePath(%q) = %q, want %q", tc.raw, path, tc.path)
		} else if p.s != tc.after {
			t.Errorf("parser.parseReversePath(%q): got after = %q, want %q", tc.raw, p.s, tc.after)
		}
	}

	invalidReversePaths := []string{
		"",
		" ",
		"asdf",
		"<Foo Bar <root@nsa.gov>>",
		" BODY=8BITMIME SIZE=12345",
		"a:b:c@example.org",
		"<root@nsa.gov",
		"<Postmaster>",
		"<postmaster>",
		`<"postmaster">`,
		"postmaster",
		"<a\x01b@example.org>",
		"<a\x00b@example.org>",
		"<a\x7fb@example.org>",
		"<\"a\x01b\"@example.org>",
		"<\"a\x00b\"@example.org>",
		"<\"a\x7fb\"@example.org>",
		"<\"a\\\x01b\"@example.org>",
		"<\"a\\\x00b\"@example.org>",
	}
	for _, tc := range invalidReversePaths {
		p := parser{tc}
		if path, err := p.parseReversePath(); err == nil {
			t.Errorf("parser.parseReversePath(%q) = %q, want error", tc, path)
		}
	}
}

// Leading, trailing and consecutive dots are not a valid RFC 5321 Dot-string,
// but older Japanese carrier addresses (docomo, au/ezweb, SoftBank) still use
// them and Postfix accepts them, so both paths accept them and hand the
// address back unchanged (Open-Email/smtp-in#108).
func TestParserLegacyDottedLocalParts(t *testing.T) {
	cases := []struct {
		raw, path, after string
	}{
		{"<taro..yamada@docomo.ne.jp>", "taro..yamada@docomo.ne.jp", ""},
		{"<foo.@ezweb.ne.jp>", "foo.@ezweb.ne.jp", ""},
		{"<.foo@example.com>", ".foo@example.com", ""},
		{"<.a..b.@example.com> SIZE=10", ".a..b.@example.com", " SIZE=10"},
		{"taro..yamada@docomo.ne.jp", "taro..yamada@docomo.ne.jp", ""},
	}
	parsers := []struct {
		name  string
		parse func(*parser) (string, error)
	}{
		{"parseReversePath", (*parser).parseReversePath},
		{"parseForwardPath", (*parser).parseForwardPath},
	}
	for _, pp := range parsers {
		for _, tc := range cases {
			p := parser{tc.raw}
			path, err := pp.parse(&p)
			if err != nil {
				t.Errorf("parser.%s(%q) = %v", pp.name, tc.raw, err)
			} else if path != tc.path {
				t.Errorf("parser.%s(%q) = %q, want %q", pp.name, tc.raw, path, tc.path)
			} else if p.s != tc.after {
				t.Errorf("parser.%s(%q): got after = %q, want %q", pp.name, tc.raw, p.s, tc.after)
			}
		}
	}
}

// Accepting legacy dots must not loosen anything else: control characters,
// NUL, whitespace and the RFC 5322 specials other than '.' stay refused in an
// unquoted local part on both paths, dotted or not.
func TestParserLocalPartRefusals(t *testing.T) {
	cases := []string{
		"<a\x01b@example.org>",
		"<a\x00b@example.org>",
		"<a\x7fb@example.org>",
		"<a\x1fb@example.org>",
		"<taro..\x01yamada@docomo.ne.jp>",
		"<foo.\x00@ezweb.ne.jp>",
		"<.\x7ffoo@example.com>",
		"<a b@example.org>",
		"<a\tb@example.org>",
		"<a(b@example.org>",
		"<a)b@example.org>",
		"<a,b@example.org>",
		"<a;b@example.org>",
		"<a[b@example.org>",
		"<a]b@example.org>",
		"<a\\b@example.org>",
		"<a\"b@example.org>",
		"<a<b@example.org>",
		"<a..b,c@example.org>",
		"<\"a\x01b\"@example.org>",
		"<\"a\x00b\"@example.org>",
	}
	parsers := []struct {
		name  string
		parse func(*parser) (string, error)
	}{
		{"parseReversePath", (*parser).parseReversePath},
		{"parseForwardPath", (*parser).parseForwardPath},
	}
	for _, pp := range parsers {
		for _, tc := range cases {
			p := parser{tc}
			if path, err := pp.parse(&p); err == nil {
				t.Errorf("parser.%s(%q) = %q, want error", pp.name, tc, path)
			}
		}
	}
}

func TestParseCmd(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedCmd string
		expectedArg string
		shouldError bool
	}{
		{
			name:        "XCLIENT command with arguments",
			input:       "XCLIENT ADDR=127.0.0.1 PORT=55804 PROTO=ESMTP",
			expectedCmd: "XCLIENT",
			expectedArg: "ADDR=127.0.0.1 PORT=55804 PROTO=ESMTP",
			shouldError: false,
		},
		{
			name:        "MAIL command",
			input:       "MAIL FROM:<test@example.com>",
			expectedCmd: "MAIL",
			expectedArg: "FROM:<test@example.com>",
			shouldError: false,
		},
		{
			name:        "STARTTLS command (special case)",
			input:       "STARTTLS",
			expectedCmd: "STARTTLS",
			expectedArg: "",
			shouldError: false,
		},
		{
			name:        "QUIT command no args",
			input:       "QUIT",
			expectedCmd: "QUIT",
			expectedArg: "",
			shouldError: false,
		},
		{
			name:        "EHLO command",
			input:       "EHLO localhost",
			expectedCmd: "EHLO",
			expectedArg: "localhost",
			shouldError: false,
		},
		{
			name:        "LHLO command",
			input:       "LHLO localhost",
			expectedCmd: "LHLO",
			expectedArg: "localhost",
			shouldError: false,
		},
		{
			name:        "Long command name",
			input:       "TESTCOMMAND args here",
			expectedCmd: "TESTCOMMAND",
			expectedArg: "args here",
			shouldError: false,
		},
		{
			name:        "Command too short",
			input:       "HI",
			expectedCmd: "",
			expectedArg: "",
			shouldError: true,
		},
		{
			name:        "Command with CRLF",
			input:       "XCLIENT ADDR=127.0.0.1\r\n",
			expectedCmd: "XCLIENT",
			expectedArg: "ADDR=127.0.0.1",
			shouldError: false,
		},
		{
			name:        "Empty line",
			input:       "",
			expectedCmd: "",
			expectedArg: "",
			shouldError: false,
		},
		{
			name:        "Case insensitive command",
			input:       "xclient addr=127.0.0.1",
			expectedCmd: "XCLIENT",
			expectedArg: "addr=127.0.0.1",
			shouldError: false,
		},
		{
			name:        "Very short command with space",
			input:       "AB args",
			expectedCmd: "",
			expectedArg: "",
			shouldError: true,
		},
		{
			name:        "Minimum valid command with args",
			input:       "TEST arg",
			expectedCmd: "TEST",
			expectedArg: "arg",
			shouldError: false,
		},
		{
			name:        "Command with extra spaces in args",
			input:       "RCPT  TO:<user@example.com>  ",
			expectedCmd: "RCPT",
			expectedArg: "TO:<user@example.com>",
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, arg, err := parseCmd(tt.input)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if cmd != tt.expectedCmd {
				t.Errorf("Expected command %q, got %q", tt.expectedCmd, cmd)
			}

			if arg != tt.expectedArg {
				t.Errorf("Expected argument %q, got %q", tt.expectedArg, arg)
			}
		})
	}
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		raw  string
		want map[string]string
	}{
		{" BODY=8BITMIME SIZE=1024 SMTPUTF8", map[string]string{
			"BODY": "8BITMIME", "SIZE": "1024", "SMTPUTF8": "",
		}},
		// Values may contain '=', e.g. base64 padding in AUTH (RFC 4954)
		// or xtext-free ORCPT values; only the first '=' separates the key.
		{" AUTH=dXNlcg==", map[string]string{"AUTH": "dXNlcg=="}},
		{" ORCPT=rfc822;user=x@example.org", map[string]string{
			"ORCPT": "rfc822;user=x@example.org",
		}},
	}
	for _, tc := range tests {
		got, err := parseArgs(tc.raw)
		if err != nil {
			t.Errorf("parseArgs(%q) = %v", tc.raw, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("parseArgs(%q) = %v, want %v", tc.raw, got, tc.want)
			continue
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("parseArgs(%q)[%q] = %q, want %q", tc.raw, k, got[k], v)
			}
		}
	}
}

func TestESMTPParametersRequireBracketedPath(t *testing.T) {
	for _, raw := range []string{"user@example.com SIZE=100", "user@example.com SMTPUTF8", "user@example.com NOTIFY=SUCCESS", "user@example.com\tSMTPUTF8"} {
		for _, forward := range []bool{false, true} {
			p := parser{raw}
			var err error
			if forward {
				_, err = p.parseForwardPath()
			} else {
				_, err = p.parseReversePath()
			}
			if err == nil {
				t.Errorf("unbracketed path with parameters accepted: %q (forward=%v)", raw, forward)
			}
		}
	}
}
