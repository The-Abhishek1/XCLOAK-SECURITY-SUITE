package services

import (
	"strings"
)

// EvaluateCondition evaluates a Sigma-lite boolean condition string against
// a map of selection_name -> bool (whether that selection matched).
//
// Grammar (case-insensitive keywords "and", "or", "not"):
//
//	expr   := term (("and" | "or") term)*
//	term   := "not" factor | factor
//	factor := IDENT | "(" expr ")"
//
// Operators are left-associative and evaluated left-to-right with equal
// precedence (no AND-before-OR precedence) — this matches how most simple
// Sigma conditions read naturally and keeps the implementation small.
// Use parentheses for explicit grouping when mixing and/or.
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

// tokenizeCondition splits a condition string into tokens: identifiers,
// "and", "or", "not", "(", ")". Identifiers may contain letters, digits,
// and underscores (typical Sigma selection names like "selection1").
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

func (p *conditionParser) next() string {
	t := p.peek()
	p.pos++
	return t
}

// parseExpr := term (("and" | "or") term)*
func (p *conditionParser) parseExpr() (bool, bool) {

	left, ok := p.parseTerm()
	if !ok {
		return false, false
	}

	for {
		op := p.peek()
		if op != "and" && op != "or" {
			break
		}
		p.next()

		right, ok := p.parseTerm()
		if !ok {
			return false, false
		}

		if op == "and" {
			left = left && right
		} else {
			left = left || right
		}
	}

	return left, true
}

// term := "not" factor | factor
func (p *conditionParser) parseTerm() (bool, bool) {

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

// factor := IDENT | "(" expr ")"
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

	if tok == "and" || tok == "or" || tok == "not" || tok == ")" {
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
