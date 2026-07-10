package services

import (
	"strings"
)

// EvaluateCondition evaluates a Sigma condition string against a map of
// selection_name -> bool (whether that selection matched).
//
// Grammar (case-insensitive keywords):
//
//	expr       := orExpr
//	orExpr     := andExpr ("or" andExpr)*
//	andExpr    := notExpr ("and" notExpr)*
//	notExpr    := "not" factor | factor
//	factor     := quantifier | IDENT | "(" expr ")"
//	quantifier := ("1" | "all") "of" target
//	target     := "them" | IDENT-with-optional-wildcard
//
// Precedence matches standard Sigma/boolean convention: NOT binds tightest,
// then AND, then OR — so "a or b and c" means "a or (b and c)". Use
// parentheses to override.
//
// Quantifiers match real Sigma syntax:
//   - "1 of them"         — at least one selection (of all defined) matched
//   - "all of them"       — every defined selection matched
//   - "1 of selection*"   — at least one selection whose name matches the
//     glob (e.g. "selection*", "filter_*") matched
//   - "all of selection*" — every selection matching the glob matched
//
// An empty condition string falls back to "true if ANY selection matched"
// (OR of all selections) — this preserves the old flat-keyword behavior.
func EvaluateCondition(condition string, results map[string]bool) bool {

	condition = strings.TrimSpace(condition)

	if condition == "" {
		for _, v := range results {
			if v {
				return true
			}
		}
		return false
	}

	tokens := tokenizeCondition(condition)
	p := &conditionParser{tokens: tokens, pos: 0, results: results}

	val, ok := p.parseExpr()
	if !ok {
		// Malformed condition — fail safe to "no match" rather than
		// risk a flood of false-positive alerts.
		return false
	}

	return val
}

// tokenizeCondition splits a condition string into tokens: identifiers
// (which may include "*" for wildcard quantifier targets), "and", "or",
// "not", "of", "(", ")".
func tokenizeCondition(s string) []string {

	var tokens []string
	var cur strings.Builder

	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}

	for _, r := range s {
		switch {
		case r == '(' || r == ')':
			flush()
			tokens = append(tokens, string(r))
		case r == ' ' || r == '\t' || r == '\n':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()

	return tokens
}

type conditionParser struct {
	tokens  []string
	pos     int
	results map[string]bool
}

func (p *conditionParser) peek() string {
	if p.pos < len(p.tokens) {
		return strings.ToLower(p.tokens[p.pos])
	}
	return ""
}

// peekAt looks ahead n tokens from the current position without consuming.
func (p *conditionParser) peekAt(n int) string {
	if p.pos+n < len(p.tokens) {
		return strings.ToLower(p.tokens[p.pos+n])
	}
	return ""
}

func (p *conditionParser) next() string {
	t := p.peek()
	p.pos++
	return t
}

// parseExpr is the entry point — OR has the lowest precedence.
func (p *conditionParser) parseExpr() (bool, bool) {
	return p.parseOr()
}

// orExpr := andExpr ("or" andExpr)*
func (p *conditionParser) parseOr() (bool, bool) {

	left, ok := p.parseAnd()
	if !ok {
		return false, false
	}

	for p.peek() == "or" {
		p.next()
		right, ok := p.parseAnd()
		if !ok {
			return false, false
		}
		left = left || right
	}

	return left, true
}

// andExpr := notExpr ("and" notExpr)*
func (p *conditionParser) parseAnd() (bool, bool) {

	left, ok := p.parseNot()
	if !ok {
		return false, false
	}

	for p.peek() == "and" {
		p.next()
		right, ok := p.parseNot()
		if !ok {
			return false, false
		}
		left = left && right
	}

	return left, true
}

// notExpr := "not" factor | factor
func (p *conditionParser) parseNot() (bool, bool) {

	if p.peek() == "not" {
		p.next()
		val, ok := p.parseFactor()
		if !ok {
			return false, false
		}
		return !val, true
	}

	return p.parseFactor()
}

// factor := quantifier | IDENT | "(" expr ")"
func (p *conditionParser) parseFactor() (bool, bool) {

	tok := p.peek()

	if tok == "" {
		return false, false
	}

	if tok == "(" {
		p.next()
		val, ok := p.parseExpr()
		if !ok {
			return false, false
		}
		if p.peek() != ")" {
			return false, false
		}
		p.next()
		return val, true
	}

	// Quantifier: "1 of <target>" / "all of <target>".
	if (tok == "1" || tok == "all") && p.peekAt(1) == "of" {
		quant := tok
		p.next() // consume "1" / "all"
		p.next() // consume "of"
		target := p.next()
		return p.evalQuantifier(quant, target), true
	}

	if tok == "and" || tok == "or" || tok == "not" || tok == ")" || tok == "of" {
		return false, false
	}

	// Identifier — look up the original-case token in results.
	// Selection names are matched case-insensitively.
	p.next()
	for name, val := range p.results {
		if strings.EqualFold(name, tok) {
			return val, true
		}
	}
	// Unknown selection name referenced — treat as false rather than error,
	// so a typo in one selection doesn't crash the whole engine.
	return false, true
}

// evalQuantifier handles "1 of <target>" / "all of <target>", where target
// is "them" (every selection) or a possibly-wildcarded selection name.
func (p *conditionParser) evalQuantifier(quant, target string) bool {

	matchAll := quant == "all"
	matchEverything := target == "them"

	matched, total := 0, 0
	for name, val := range p.results {
		if !matchEverything && !globMatch(strings.ToLower(name), target) {
			continue
		}
		total++
		if val {
			matched++
		}
	}

	if total == 0 {
		return false
	}
	if matchAll {
		return matched == total
	}
	return matched >= 1
}

// globMatch supports "*" wildcards anywhere in pattern (Sigma selection
// names typically use a single trailing wildcard, e.g. "selection*", but
// this handles multiple segments too).
func globMatch(name, pattern string) bool {

	if !strings.Contains(pattern, "*") {
		return name == pattern
	}

	parts := strings.Split(pattern, "*")

	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	rest := name[len(parts[0]):]

	for _, part := range parts[1 : len(parts)-1] {
		if part == "" {
			continue
		}
		idx := strings.Index(rest, part)
		if idx == -1 {
			return false
		}
		rest = rest[idx+len(part):]
	}

	last := parts[len(parts)-1]
	return last == "" || strings.HasSuffix(rest, last)
}
