package supplychain

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

const minSplitEncodedLen = 192

var (
	reZlibGzipDecompress    = regexp.MustCompile(`(?i)(\b(?:zlib\.(?:decompress|inflateSync|inflateRawSync|gunzipSync)|gzip\.decompress)|:zlib\.(?:uncompress|gunzip))\s*\(`)
	reFromCharCode          = regexp.MustCompile(`String\.fromCharCode\s*\(([^)]+)\)`)
	reNumericArg            = regexp.MustCompile(`\b(?:0x[0-9a-fA-F]+|\d+)\b`)
	reBufferFromEncoded     = regexp.MustCompile(`Buffer\.from\s*\([^\n]*,\s*['"](base64|hex)['"]\s*\)`)
	rePythonMarshalLoads    = regexp.MustCompile(`\bmarshal\.loads\s*\(`)
	rePythonCodecsDecode    = regexp.MustCompile(`\bcodecs\.decode\s*\([^\n]*,\s*['"](rot_?13|base64|hex)['"]\s*\)`)
	rePythonGetattrBuiltins = regexp.MustCompile(`\bgetattr\s*\(\s*__?builtins__?\s*,`)
	reElixirBinaryToTerm    = regexp.MustCompile(`:erlang\.binary_to_term\s*\(`)
)

// ScanMultiLineObfuscationAndDynamicExec detects split/array-joined Base64/hex
// payloads (>= 192 cumulative encoded chars), zlib/gzip decompression paired
// with dynamic execution, String.fromCharCode/Buffer.from obfuscation + exec,
// Python marshal.loads/codecs.decode/getattr(__builtins__, ...), and Elixir
// :erlang.binary_to_term calls missing the :safe option.
func ScanMultiLineObfuscationAndDynamicExec(relPath, content string, isTestFile bool) []types.SecurityFinding {
	var findings []types.SecurityFinding
	seenIDs := make(map[string]bool)
	addFinding := func(f types.SecurityFinding) {
		if seenIDs[f.ID] {
			return
		}
		seenIDs[f.ID] = true
		findings = append(findings, f)
	}

	ext := strings.ToLower(filepath.Ext(relPath))
	isGo := ext == ".go"
	hasExec := hasExecSink(content)

	// 1. Split / array-joined Base64 or hex payloads (>= 192 cumulative encoded chars)
	if matchLine, matchKind := findSplitEncodedPayload(content, isGo); matchLine > 0 {
		if hasExec {
			addFinding(types.SecurityFinding{
				ID:          "malware-obfuscated-exec-dropper",
				Category:    types.CategoryMalware,
				Tool:        "supplychain",
				Severity:    types.SeverityCritical,
				Title:       fmt.Sprintf("Multi-line obfuscated %s paired with dynamic execution in %s", matchKind, relPath),
				Description: "Split or array-joined encoded payload paired with eval/exec/process-spawning primitives indicates an obfuscated malware dropper.",
				FilePath:    relPath,
				Line:        matchLine,
				CWE:         "CWE-506",
			})
		} else if !isTestFile {
			addFinding(types.SecurityFinding{
				ID:          "supplychain-suspicious-encoded-blob",
				Category:    types.CategorySupplyChain,
				Tool:        "supplychain",
				Severity:    types.SeverityHigh,
				Title:       fmt.Sprintf("Suspicious split %s in %s", matchKind, relPath),
				Description: "Large split Base64 or hex literal sequence (>= 192 cumulative encoded chars) found outside allowlisted paths or test fixtures.",
				FilePath:    relPath,
				Line:        matchLine,
				CWE:         "CWE-506",
			})
		}
	}

	// 2. zlib/gzip decompression paired with dynamic execution
	if hasExec && !isGo {
		if line := findRegexLineOutsideComments(content, reZlibGzipDecompress); line > 0 {
			addFinding(types.SecurityFinding{
				ID:          "malware-obfuscated-exec-dropper",
				Category:    types.CategoryMalware,
				Tool:        "supplychain",
				Severity:    types.SeverityCritical,
				Title:       fmt.Sprintf("Compressed payload decompression paired with dynamic execution in %s", relPath),
				Description: "Detected zlib/gzip decompression alongside dynamic code or command execution primitives.",
				FilePath:    relPath,
				Line:        line,
				CWE:         "CWE-506",
			})
		}
	}

	// 3. String.fromCharCode (>= 8 char codes) / Buffer.from(..., 'base64'|'hex') + exec
	if !isGo {
		if line := findFromCharCodeDropper(content, hasExec); line > 0 {
			addFinding(types.SecurityFinding{
				ID:          "malware-obfuscated-exec-dropper",
				Category:    types.CategoryMalware,
				Tool:        "supplychain",
				Severity:    types.SeverityCritical,
				Title:       fmt.Sprintf("String.fromCharCode obfuscation paired with dynamic execution in %s", relPath),
				Description: "Detected String.fromCharCode with 8 or more character codes alongside dynamic execution primitives.",
				FilePath:    relPath,
				Line:        line,
				CWE:         "CWE-506",
			})
		}
		if hasExec {
			if line := findRegexLineOutsideComments(content, reBufferFromEncoded); line > 0 {
				addFinding(types.SecurityFinding{
					ID:          "malware-obfuscated-exec-dropper",
					Category:    types.CategoryMalware,
					Tool:        "supplychain",
					Severity:    types.SeverityCritical,
					Title:       fmt.Sprintf("Buffer.from base64/hex decoding paired with dynamic execution in %s", relPath),
					Description: "Detected Buffer.from(..., 'base64'|'hex') paired with dynamic execution primitives in the same file.",
					FilePath:    relPath,
					Line:        line,
					CWE:         "CWE-506",
				})
			}
		}
	}

	// 4. Python marshal.loads / codecs.decode / getattr(__builtins__, ...)
	if !isGo {
		if line := findRegexLineOutsideComments(content, rePythonMarshalLoads); line > 0 {
			addFinding(types.SecurityFinding{
				ID:          "malware-unsafe-deserialization-exec",
				Category:    types.CategoryMalware,
				Tool:        "supplychain",
				Severity:    types.SeverityCritical,
				Title:       fmt.Sprintf("Unsafe Python marshal.loads bytecode deserialization in %s", relPath),
				Description: "marshal.loads deserializes arbitrary Python code objects and is a common vector for obfuscated payload execution.",
				FilePath:    relPath,
				Line:        line,
				CWE:         "CWE-502",
			})
		}
		if hasExec || !isTestFile {
			if line := findRegexLineOutsideComments(content, rePythonCodecsDecode); line > 0 {
				addFinding(types.SecurityFinding{
					ID:          "malware-obfuscated-exec-dropper",
					Category:    types.CategoryMalware,
					Tool:        "supplychain",
					Severity:    types.SeverityCritical,
					Title:       fmt.Sprintf("Obfuscated Python codecs.decode payload in %s", relPath),
					Description: "Detected codecs.decode with rot13/base64/hex encoding used to obfuscate executable payloads.",
					FilePath:    relPath,
					Line:        line,
					CWE:         "CWE-506",
				})
			}
		}
		if line := findRegexLineOutsideComments(content, rePythonGetattrBuiltins); line > 0 {
			addFinding(types.SecurityFinding{
				ID:          "malware-obfuscated-exec-dropper",
				Category:    types.CategoryMalware,
				Tool:        "supplychain",
				Severity:    types.SeverityCritical,
				Title:       fmt.Sprintf("Dynamic __builtins__ lookup via getattr in %s", relPath),
				Description: "Using getattr(__builtins__, ...) dynamically resolves eval/exec/__import__ to evade static analysis.",
				FilePath:    relPath,
				Line:        line,
				CWE:         "CWE-506",
			})
		}
	}

	// 5. Elixir :erlang.binary_to_term lacking :safe
	if !isGo {
		if line := findUnsafeElixirBinaryToTerm(content); line > 0 {
			addFinding(types.SecurityFinding{
				ID:          "malware-unsafe-deserialization-exec",
				Category:    types.CategoryMalware,
				Tool:        "supplychain",
				Severity:    types.SeverityCritical,
				Title:       fmt.Sprintf("Unsafe Elixir :erlang.binary_to_term without :safe in %s", relPath),
				Description: ":erlang.binary_to_term/1-2 without the [:safe] option permits arbitrary atom creation and unsafe term/function deserialization.",
				FilePath:    relPath,
				Line:        line,
				CWE:         "CWE-502",
			})
		}
	}

	return findings
}

type stringLiteralToken struct {
	value    string
	startPos int
	endPos   int
	line     int
}

func extractQuotedLiterals(content string, isGo bool) []stringLiteralToken {
	var tokens []stringLiteralToken
	n := len(content)
	line := 1

	for i := 0; i < n; {
		c := content[i]
		if c == '\n' {
			line++
			i++
			continue
		}
		// Skip // comments
		if c == '/' && i+1 < n && content[i+1] == '/' {
			for i < n && content[i] != '\n' {
				i++
			}
			continue
		}
		// Skip /* ... */ comments
		if c == '/' && i+1 < n && content[i+1] == '*' {
			i += 2
			for i < n {
				if content[i] == '\n' {
					line++
				}
				if content[i] == '*' && i+1 < n && content[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
			continue
		}
		// Skip # comments
		if c == '#' {
			for i < n && content[i] != '\n' {
				i++
			}
			continue
		}
		// Triple-quoted strings: """...""" or '''...'''
		if (c == '"' || c == '\'') && i+2 < n && content[i+1] == c && content[i+2] == c {
			q := c
			startPos := i
			startLine := line
			i += 3
			var buf strings.Builder
			closed := false
			for i < n {
				if content[i] == '\\' && i+1 < n {
					if content[i+1] == 'x' {
						buf.WriteByte(content[i])
						buf.WriteByte(content[i+1])
						i += 2
						continue
					}
					buf.WriteByte(content[i+1])
					if content[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if content[i] == q && i+2 < n && content[i+1] == q && content[i+2] == q {
					i += 3
					closed = true
					break
				}
				if content[i] == '\n' {
					line++
				}
				buf.WriteByte(content[i])
				i++
			}
			if closed {
				tokens = append(tokens, stringLiteralToken{
					value:    buf.String(),
					startPos: startPos,
					endPos:   i,
					line:     startLine,
				})
			}
			continue
		}
		// Backtick template/raw string literal: `...`
		if c == '`' {
			startPos := i
			startLine := line
			i++
			var buf strings.Builder
			closed := false
			for i < n {
				if !isGo && content[i] == '\\' && i+1 < n {
					if content[i+1] == 'x' {
						buf.WriteByte(content[i])
						buf.WriteByte(content[i+1])
						i += 2
						continue
					}
					buf.WriteByte(content[i+1])
					if content[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if content[i] == '`' {
					i++
					closed = true
					break
				}
				if content[i] == '\n' {
					line++
				}
				buf.WriteByte(content[i])
				i++
			}
			if closed {
				tokens = append(tokens, stringLiteralToken{
					value:    buf.String(),
					startPos: startPos,
					endPos:   i,
					line:     startLine,
				})
			}
			continue
		}
		if c == '"' || c == '\'' {
			q := c
			startPos := i
			startLine := line
			i++
			var buf strings.Builder
			closed := false
			for i < n {
				if content[i] == '\\' && i+1 < n {
					// Preserve \xNN sequences verbatim for hex-escape detection
					if content[i+1] == 'x' {
						buf.WriteByte(content[i])
						buf.WriteByte(content[i+1])
						i += 2
						continue
					}
					buf.WriteByte(content[i+1])
					if content[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if content[i] == q {
					i++
					closed = true
					break
				}
				if content[i] == '\n' {
					line++
					i++
					break
				}
				buf.WriteByte(content[i])
				i++
			}
			if closed {
				tokens = append(tokens, stringLiteralToken{
					value:    buf.String(),
					startPos: startPos,
					endPos:   i,
					line:     startLine,
				})
			}
			continue
		}
		i++
	}
	return tokens
}

func isOnlyConcatSeparator(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\r', '\n', '+', ',':
		default:
			return false
		}
	}
	return true
}

func findSplitEncodedPayload(content string, isGo bool) (int, string) {
	tokens := extractQuotedLiterals(content, isGo)
	if len(tokens) < 2 {
		return 0, ""
	}

	i := 0
	for i < len(tokens) {
		groupStart := i
		var joined strings.Builder
		joined.WriteString(tokens[i].value)
		for i+1 < len(tokens) && isOnlyConcatSeparator(content[tokens[i].endPos:tokens[i+1].startPos]) {
			i++
			joined.WriteString(tokens[i].value)
		}
		groupLen := i - groupStart + 1
		if groupLen >= 2 {
			combined := joined.String()
			lineStart := strings.LastIndexByte(content[:tokens[groupStart].startPos], '\n') + 1
			prefixLine := content[lineStart:tokens[groupStart].startPos]
			if !isBenignBase64Prefix(prefixLine, len(prefixLine)) {
				if reHexEscapedBlob.MatchString(combined) {
					return tokens[groupStart].line, "hex-escaped byte sequence"
				}
				if len(combined) >= minSplitEncodedLen {
					if isHexPayload(combined) {
						return tokens[groupStart].line, "hex payload"
					}
					if isBase64Payload(combined) {
						return tokens[groupStart].line, "Base64 payload"
					}
				}
			}
		}
		i++
	}
	return 0, ""
}

func isHexPayload(s string) bool {
	var hasDigit, hasHexAlpha bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
			hasHexAlpha = true
		default:
			return false
		}
	}
	return hasDigit && hasHexAlpha
}

func isBase64Payload(s string) bool {
	var hasUpper, hasLower, hasDigit bool
	eqCount := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == '+' || c == '/':
		case c == '=':
			eqCount++
		default:
			return false
		}
	}
	if eqCount > len(s)/4 {
		return false
	}
	return hasUpper && hasLower && hasDigit
}

func findRegexLineOutsideComments(content string, re *regexp.Regexp) int {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if re.MatchString(line) {
			return i + 1
		}
	}
	return 0
}

func findFromCharCodeDropper(content string, hasExec bool) int {
	hasDynamicRef := hasExec ||
		strings.Contains(content, "globalThis[") ||
		strings.Contains(content, "window[") ||
		strings.Contains(content, "global[") ||
		strings.Contains(content, "Function")
	if !hasDynamicRef {
		return 0
	}
	matches := reFromCharCode.FindAllStringSubmatchIndex(content, -1)
	for _, m := range matches {
		args := content[m[2]:m[3]]
		if len(reNumericArg.FindAllString(args, -1)) >= 8 {
			return 1 + strings.Count(content[:m[0]], "\n")
		}
	}
	return 0
}

func findUnsafeElixirBinaryToTerm(content string) int {
	locs := reElixirBinaryToTerm.FindAllStringIndex(content, -1)
	for _, loc := range locs {
		lineStart := strings.LastIndexByte(content[:loc[0]], '\n') + 1
		if strings.HasPrefix(strings.TrimSpace(content[lineStart:loc[0]]), "#") {
			continue
		}
		// Extract balanced argument list starting at the '(' at loc[1]-1
		depth := 1
		end := loc[1]
		for end < len(content) && depth > 0 {
			switch content[end] {
			case '(':
				depth++
			case ')':
				depth--
			}
			end++
		}
		args := content[loc[1]:end]
		if !strings.Contains(args, ":safe") {
			return 1 + strings.Count(content[:loc[0]], "\n")
		}
	}
	return 0
}
