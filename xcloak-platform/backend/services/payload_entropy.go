package services

// Payload entropy utilities used across all DPI detectors.
//
// EntropyScore returns a 0-100 score where 100 = maximum randomness
// (encrypted / compressed / base64) and 0 = fully repetitive / dictionary text.
//
// DGA ngram model approximates English language bigram probability so that
// human-readable domains score low and randomly generated ones score high.

import (
	"math"
	"strings"
	"unicode"
)

// ShannonEntropy returns the per-character Shannon entropy (bits) for s.
// Typical values: English text ≈3.0–3.5, random hex ≈3.8, random b64 ≈4.2.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len(s))
	var entropy float64
	for _, count := range freq {
		p := count / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// EntropyScore normalises ShannonEntropy to a 0–100 integer scale.
// 0 bits → 0; 4.5+ bits → 100 (base64 ceiling).
func EntropyScore(s string) int {
	e := ShannonEntropy(s)
	score := int(e / 4.5 * 100)
	if score > 100 {
		score = 100
	}
	return score
}

// DGAScore returns a 0–100 score estimating how likely a domain label is to be
// algorithmically generated. Combines:
//   - Shannon entropy of the label
//   - Bigram likelihood against English frequency
//   - Digit ratio (DGA domains often mix digits)
//   - Consonant cluster length (DGA = many consecutive consonants)
//   - Label length (very long labels = suspicious)
func DGAScore(label string) int {
	if len(label) < 6 {
		return 0
	}
	label = strings.ToLower(label)

	score := 0

	// Component 1: entropy
	entropy := ShannonEntropy(label)
	switch {
	case entropy >= 4.0:
		score += 40
	case entropy >= 3.6:
		score += 28
	case entropy >= 3.2:
		score += 16
	case entropy >= 2.8:
		score += 8
	}

	// Component 2: English bigram log-likelihood deviation
	bigramPenalty := bigramDeviation(label)
	score += min100p(int(bigramPenalty * 30))

	// Component 3: digit ratio
	digits := 0
	for _, c := range label {
		if c >= '0' && c <= '9' {
			digits++
		}
	}
	digitRatio := float64(digits) / float64(len(label))
	switch {
	case digitRatio >= 0.4:
		score += 20
	case digitRatio >= 0.25:
		score += 10
	case digitRatio >= 0.15:
		score += 5
	}

	// Component 4: consonant cluster (≥4 in a row)
	vowels := map[rune]bool{'a': true, 'e': true, 'i': true, 'o': true, 'u': true}
	maxCluster, cur := 0, 0
	for _, c := range label {
		if !unicode.IsLetter(c) {
			cur = 0
			continue
		}
		if vowels[c] {
			cur = 0
		} else {
			cur++
			if cur > maxCluster {
				maxCluster = cur
			}
		}
	}
	if maxCluster >= 5 {
		score += 15
	} else if maxCluster >= 4 {
		score += 8
	}

	// Component 5: suspicious length
	if len(label) >= 25 {
		score += 15
	} else if len(label) >= 18 {
		score += 8
	}

	if score > 100 {
		score = 100
	}
	return score
}

// bigramDeviation returns 0.0–1.0: how far the observed bigram distribution
// diverges from typical English text. 0.0 = English-like, 1.0 = pure noise.
func bigramDeviation(s string) float64 {
	if len(s) < 2 {
		return 0
	}
	// Common English bigrams in rough frequency order.
	// We score by the fraction of bigrams that are NOT in the top-50 English list.
	common := commonBigrams()
	total := 0
	uncommon := 0
	for i := 0; i < len(s)-1; i++ {
		bg := string(s[i]) + string(s[i+1])
		total++
		if _, ok := common[bg]; !ok {
			uncommon++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(uncommon) / float64(total)
}

// commonBigrams returns the set of 80 most common English bigrams.
func commonBigrams() map[string]struct{} {
	top := []string{
		"th", "he", "in", "en", "nt", "re", "er", "an", "ti", "es",
		"on", "at", "se", "nd", "or", "ar", "al", "te", "co", "de",
		"to", "ra", "et", "ed", "it", "sa", "em", "ro", "is", "be",
		"ha", "ng", "as", "me", "hi", "ns", "ld", "le", "to", "ne",
		"ll", "la", "ri", "ot", "li", "mo", "no", "ve", "st", "el",
		"si", "ch", "ec", "ac", "om", "ic", "ce", "ca", "rs", "ma",
		"ge", "io", "ea", "ct", "ou", "ho", "na", "ew", "ad", "fo",
		"gh", "ss", "pe", "vi", "tr", "un", "up", "ly", "ow", "ut",
	}
	m := make(map[string]struct{}, len(top))
	for _, b := range top {
		m[b] = struct{}{}
	}
	return m
}

// URLPathEntropy returns entropy of a URL path component.
// High entropy = likely obfuscated path / webshell with random filename.
func URLPathEntropy(path string) float64 {
	// Strip leading slash and query string.
	path = strings.TrimPrefix(path, "/")
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	// Take the final path component.
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		path = path[i+1:]
	}
	// Strip extension.
	if i := strings.LastIndexByte(path, '.'); i >= 0 {
		path = path[:i]
	}
	return ShannonEntropy(path)
}

// IsBase64Encoded returns true when s looks like a base64 blob (charset + padding).
func IsBase64Encoded(s string) bool {
	if len(s) < 16 {
		return false
	}
	b64chars := 0
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			b64chars++
		}
	}
	ratio := float64(b64chars) / float64(len(s))
	return ratio >= 0.90 && ShannonEntropy(s) >= 3.5
}

func min100p(n int) int {
	if n > 100 {
		return 100
	}
	return n
}
