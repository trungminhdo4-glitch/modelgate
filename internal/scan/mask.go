package scan

// maskPython returns a copy of src in which string literals and comments are
// replaced by spaces. Length, byte offsets and newline positions are preserved
// exactly, so a match index in the masked text is also a valid index in the
// original source. Structural pattern rules run on the masked text, which
// keeps examples inside comments and strings from firing.
//
// The masker never executes or imports anything; it is a pure byte-level
// transformation and therefore safe on untrusted model code.
func maskPython(src []byte) []byte {
	out := make([]byte, len(src))
	copy(out, src)

	i, n := 0, len(src)
	for i < n {
		c := out[i]
		switch {
		case c == '#':
			// Comment: blank everything up to (but not including) the newline.
			for i < n && out[i] != '\n' {
				out[i] = ' '
				i++
			}

		case c == '"' || c == '\'':
			q := c
			if i+2 < n && out[i+1] == q && out[i+2] == q {
				i = maskTripleString(out, i, q)
				continue
			}
			i = maskSingleLineString(out, i, q)

		default:
			i++
		}
	}
	return out
}

// maskTripleString masks a ”' or """ literal starting at i and returns the
// index just after it (or end of input if it is never terminated).
func maskTripleString(out []byte, i int, q byte) int {
	n := len(out)
	out[i], out[i+1], out[i+2] = ' ', ' ', ' '
	i += 3
	for i < n {
		switch {
		case out[i] == '\\':
			out[i] = ' '
			if i+1 < n && out[i+1] != '\n' {
				out[i+1] = ' '
			}
			i += 2
		case out[i] == q && i+2 < n && out[i+1] == q && out[i+2] == q:
			out[i], out[i+1], out[i+2] = ' ', ' ', ' '
			return i + 3
		default:
			if out[i] != '\n' {
				out[i] = ' '
			}
			i++
		}
	}
	return i
}

// maskSingleLineString masks a single-quoted literal starting at i. Python
// forbids an unescaped newline inside such literals, so masking stops at the
// newline and leaves it in place (malformed input must not break line math).
func maskSingleLineString(out []byte, i int, q byte) int {
	n := len(out)
	out[i] = ' '
	i++
	for i < n {
		switch {
		case out[i] == '\\':
			out[i] = ' '
			if i+1 < n && out[i+1] != '\n' {
				out[i+1] = ' '
			}
			i += 2
		case out[i] == q:
			out[i] = ' '
			return i + 1
		case out[i] == '\n':
			return i
		default:
			out[i] = ' '
			i++
		}
	}
	return i
}
