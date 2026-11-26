package supplychain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

var executableExtensions = map[string]bool{
	".exe":   true,
	".dll":   true,
	".so":    true,
	".dylib": true,
	".beam":  true,
	".pyc":   true,
	".wasm":  true,
}

func isBidiControlRune(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

func isVariationSelectorRune(r rune) bool {
	return (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF)
}

func isInvisibleUnicodeRune(r rune, byteOffset int) bool {
	if r >= 0x200B && r <= 0x200F {
		return true
	}
	switch r {
	case 0x2060, 0x3164, 0x115F, 0x1160, 0xFFA0:
		return true
	case 0xFEFF:
		return byteOffset > 0
	default:
		return false
	}
}

// ScanUnicodeAnomalies detects Trojan Source bidi overrides, Variation Selector
// steganography runs, zero-width/invisible control characters, and UTR #39
// mixed-script identifier homoglyphs outside comments and string literals.
func ScanUnicodeAnomalies(relPath, content string) []types.SecurityFinding {
	var findings []types.SecurityFinding
	line := 1
	bidiReported := false
	vsReported := false
	invisibleReported := false
	vsRun := 0

	for idx, r := range content {
		if r == '\n' {
			line++
			vsRun = 0
			continue
		}
		if !bidiReported && isBidiControlRune(r) {
			bidiReported = true
			findings = append(findings, types.SecurityFinding{
				ID:          "malware-trojan-source-unicode",
				Category:    types.CategoryMalware,
				Tool:        "supplychain",
				Severity:    types.SeverityCritical,
				Title:       fmt.Sprintf("Trojan Source bidirectional Unicode control character (U+%04X) in %s", r, relPath),
				Description: "Bidirectional override/isolate Unicode control characters (CVE-2021-42574) can disguise malicious code logic from human reviewers.",
				FilePath:    relPath,
				Line:        line,
				CWE:         "CWE-1007",
			})
		}
		if isVariationSelectorRune(r) {
			vsRun++
			if !vsReported && vsRun >= 4 {
				vsReported = true
				findings = append(findings, types.SecurityFinding{
					ID:          "malware-trojan-source-unicode",
					Category:    types.CategoryMalware,
					Tool:        "supplychain",
					Severity:    types.SeverityCritical,
					Title:       fmt.Sprintf("Invisible Unicode Variation Selector steganography run in %s", relPath),
					Description: "Detected 4 or more consecutive Unicode Variation Selector runes (U+FE00..U+FE0F or U+E0100..U+E01EF), a known steganographic malware payload technique.",
					FilePath:    relPath,
					Line:        line,
					CWE:         "CWE-506",
				})
			}
		} else {
			vsRun = 0
		}
		if !invisibleReported && isInvisibleUnicodeRune(r, idx) {
			invisibleReported = true
			findings = append(findings, types.SecurityFinding{
				ID:          "malware-invisible-unicode",
				Category:    types.CategoryMalware,
				Tool:        "supplychain",
				Severity:    types.SeverityCritical,
				Title:       fmt.Sprintf("Invisible Unicode control/filler character (U+%04X) in %s", r, relPath),
				Description: "Zero-width characters, mid-file BOMs, or Hangul fillers can conceal hidden identifiers or invisible backdoor logic.",
				FilePath:    relPath,
				Line:        line,
				CWE:         "CWE-1007",
			})
		}
	}

	if f, ok := scanMixedScriptHomoglyphIdentifiers(relPath, content); ok {
		findings = append(findings, f)
	}

	return findings
}

// stripCommentsAndStrings replaces comments (//, /* */, #) and string literals
// (""", ''', `, ", ') with spaces while preserving newline characters so line
// numbers remain exact.
func stripCommentsAndStrings(relPath, content string) string {
	isGo := strings.HasSuffix(strings.ToLower(relPath), ".go")
	out := make([]byte, 0, len(content))
	n := len(content)

	for i := 0; i < n; {
		c := content[i]

		// Line comment: //
		if c == '/' && i+1 < n && content[i+1] == '/' {
			for i < n && content[i] != '\n' {
				out = append(out, ' ')
				i++
			}
			continue
		}

		// Block comment: /* ... */
		if c == '/' && i+1 < n && content[i+1] == '*' {
			out = append(out, ' ', ' ')
			i += 2
			for i < n {
				if content[i] == '*' && i+1 < n && content[i+1] == '/' {
					out = append(out, ' ', ' ')
					i += 2
					break
				}
				if content[i] == '\n' {
					out = append(out, '\n')
				} else {
					out = append(out, ' ')
				}
				i++
			}
			continue
		}

		// Hash line comment: #
		if c == '#' {
			for i < n && content[i] != '\n' {
				out = append(out, ' ')
				i++
			}
			continue
		}

		// Triple-quoted strings: """...""" or '''...'''
		if (c == '"' || c == '\'') && i+2 < n && content[i+1] == c && content[i+2] == c {
			q := c
			out = append(out, ' ', ' ', ' ')
			i += 3
			for i < n {
				if content[i] == '\\' && i+1 < n {
					if content[i+1] == '\n' {
						out = append(out, ' ', '\n')
					} else {
						out = append(out, ' ', ' ')
					}
					i += 2
					continue
				}
				if content[i] == q && i+2 < n && content[i+1] == q && content[i+2] == q {
					out = append(out, ' ', ' ', ' ')
					i += 3
					break
				}
				if content[i] == '\n' {
					out = append(out, '\n')
				} else {
					out = append(out, ' ')
				}
				i++
			}
			continue
		}

		// Backtick string literal: `...`
		if c == '`' {
			out = append(out, ' ')
			i++
			for i < n {
				if !isGo && content[i] == '\\' && i+1 < n {
					if content[i+1] == '\n' {
						out = append(out, ' ', '\n')
					} else {
						out = append(out, ' ', ' ')
					}
					i += 2
					continue
				}
				if content[i] == '`' {
					out = append(out, ' ')
					i++
					break
				}
				if content[i] == '\n' {
					out = append(out, '\n')
				} else {
					out = append(out, ' ')
				}
				i++
			}
			continue
		}

		// Single or double quoted string literal
		if c == '"' || c == '\'' {
			q := c
			out = append(out, ' ')
			i++
			for i < n {
				if content[i] == '\\' && i+1 < n {
					if content[i+1] == '\n' {
						out = append(out, ' ', '\n')
					} else {
						out = append(out, ' ', ' ')
					}
					i += 2
					continue
				}
				if content[i] == q {
					out = append(out, ' ')
					i++
					break
				}
				if content[i] == '\n' {
					out = append(out, '\n')
					i++
					break
				}
				out = append(out, ' ')
				i++
			}
			continue
		}

		out = append(out, c)
		i++
	}

	return string(out)
}

func isIdentStart(r rune) bool {
	return r == '_' || unicode.IsLetter(r)
}

func isIdentPart(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

func scanMixedScriptHomoglyphIdentifiers(relPath, content string) (types.SecurityFinding, bool) {
	stripped := stripCommentsAndStrings(relPath, content)
	line := 1
	var ident []rune

	checkIdent := func() (types.SecurityFinding, bool) {
		if len(ident) == 0 {
			return types.SecurityFinding{}, false
		}
		var hasLatin, hasCyrillic, hasGreek bool
		for _, r := range ident {
			if unicode.Is(unicode.Latin, r) {
				hasLatin = true
			} else if unicode.Is(unicode.Cyrillic, r) || (r >= 0x0400 && r <= 0x04FF) {
				hasCyrillic = true
			} else if unicode.Is(unicode.Greek, r) || (r >= 0x0370 && r <= 0x03FF) {
				hasGreek = true
			}
		}
		if hasLatin && (hasCyrillic || hasGreek) {
			name := string(ident)
			return types.SecurityFinding{
				ID:          "malware-homoglyph-identifier",
				Category:    types.CategoryMalware,
				Tool:        "supplychain",
				Severity:    types.SeverityCritical,
				Title:       fmt.Sprintf("Mixed-script homoglyph identifier %q in %s", name, relPath),
				Description: "Identifier mixes Latin characters with Cyrillic or Greek confusables (UTR #39), a technique used to spoof variables or function names.",
				FilePath:    relPath,
				Line:        line,
				CWE:         "CWE-1007",
			}, true
		}
		return types.SecurityFinding{}, false
	}

	for _, r := range stripped {
		if len(ident) == 0 {
			if isIdentStart(r) {
				ident = append(ident, r)
			}
		} else {
			if isIdentPart(r) {
				ident = append(ident, r)
			} else {
				if f, ok := checkIdent(); ok {
					return f, true
				}
				ident = ident[:0]
			}
		}
		if r == '\n' {
			if f, ok := checkIdent(); ok {
				return f, true
			}
			ident = ident[:0]
			line++
		}
	}
	return checkIdent()
}

// ScanBinaryOrOversizedFile inspects the first 16 bytes of a file (regardless
// of size or extension) to detect unapproved executable/bytecode binaries while
// permitting verified benign static media assets.
// Returns (findings, skipTextScan).
func ScanBinaryOrOversizedFile(relPath, fullPath string, size int64) ([]types.SecurityFinding, bool) {
	ext := strings.ToLower(filepath.Ext(relPath))

	var hdr [16]byte
	var header []byte
	f, err := os.Open(fullPath)
	if err == nil {
		defer f.Close()
		n, readErr := io.ReadFull(f, hdr[:])
		if readErr == nil || readErr == io.ErrUnexpectedEOF || readErr == io.EOF {
			header = hdr[:n]
		}
	}

	if kind := detectExecutableMagic(header, f, size); kind != "" {
		return []types.SecurityFinding{{
			ID:          "malware-unapproved-binary",
			Category:    types.CategoryMalware,
			Tool:        "supplychain",
			Severity:    types.SeverityCritical,
			Title:       fmt.Sprintf("Unapproved %s binary in repository: %s", kind, relPath),
			Description: fmt.Sprintf("Detected %s magic header in %s (%d bytes). Compiled executables and bytecode artifacts must not be committed to source repositories.", kind, relPath, size),
			FilePath:    relPath,
			CWE:         "CWE-506",
		}}, true
	}

	if executableExtensions[ext] {
		return []types.SecurityFinding{{
			ID:          "malware-unapproved-binary",
			Category:    types.CategoryMalware,
			Tool:        "supplychain",
			Severity:    types.SeverityCritical,
			Title:       fmt.Sprintf("Unapproved executable/bytecode file (%s) in repository: %s", ext, relPath),
			Description: fmt.Sprintf("File %s has disallowed binary/bytecode extension %s (%d bytes).", relPath, ext, size),
			FilePath:    relPath,
			CWE:         "CWE-506",
		}}, true
	}

	if isBenignMediaAsset(ext, header) {
		return nil, true
	}

	if size == 0 || size > maxTextFileBytes {
		return nil, true
	}

	return nil, false
}

func detectExecutableMagic(header []byte, f *os.File, size int64) string {
	n := len(header)
	if n >= 4 {
		// ELF: \x7fELF
		if header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' {
			return "ELF"
		}
		// Mach-O (32/64 BE/LE & Universal Fat)
		switch {
		case bytes.Equal(header[:4], []byte{0xfe, 0xed, 0xfa, 0xce}),
			bytes.Equal(header[:4], []byte{0xfe, 0xed, 0xfa, 0xcf}),
			bytes.Equal(header[:4], []byte{0xce, 0xfa, 0xed, 0xfe}),
			bytes.Equal(header[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}),
			bytes.Equal(header[:4], []byte{0xca, 0xfe, 0xba, 0xbe}):
			return "Mach-O"
		}
		// WASM: \x00asm
		if header[0] == 0x00 && header[1] == 'a' && header[2] == 's' && header[3] == 'm' {
			return "WASM"
		}
	}
	// BEAM: FOR1....BEAM
	if n >= 12 && bytes.Equal(header[:4], []byte{'F', 'O', 'R', '1'}) && bytes.Equal(header[8:12], []byte{'B', 'E', 'A', 'M'}) {
		return "BEAM"
	}
	// PE/COFF: MZ + e_lfanew at 0x3C pointing to PE\x00\x00
	if n >= 2 && header[0] == 'M' && header[1] == 'Z' && f != nil && size >= 64 {
		var offBuf [4]byte
		if _, err := f.ReadAt(offBuf[:], 0x3C); err == nil {
			peOff := int64(binary.LittleEndian.Uint32(offBuf[:]))
			if peOff >= 0 && peOff+4 <= size {
				var sig [4]byte
				if _, err := f.ReadAt(sig[:], peOff); err == nil && bytes.Equal(sig[:], []byte{'P', 'E', 0x00, 0x00}) {
					return "PE/COFF"
				}
			}
		}
	}
	return ""
}

func isBenignMediaAsset(ext string, header []byte) bool {
	n := len(header)
	switch ext {
	case ".png":
		return n >= 8 && bytes.Equal(header[:8], []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a})
	case ".jpg", ".jpeg":
		return n >= 3 && header[0] == 0xff && header[1] == 0xd8 && header[2] == 0xff
	case ".gif":
		return n >= 6 && (bytes.Equal(header[:6], []byte("GIF87a")) || bytes.Equal(header[:6], []byte("GIF89a")))
	case ".webp":
		return n >= 12 && bytes.Equal(header[:4], []byte("RIFF")) && bytes.Equal(header[8:12], []byte("WEBP"))
	case ".ico":
		return n >= 4 && (bytes.Equal(header[:4], []byte{0x00, 0x00, 0x01, 0x00}) || bytes.Equal(header[:4], []byte{0x00, 0x00, 0x02, 0x00}))
	case ".woff":
		return n >= 4 && bytes.Equal(header[:4], []byte("wOFF"))
	case ".woff2":
		return n >= 4 && bytes.Equal(header[:4], []byte("wOF2"))
	case ".ttf":
		return n >= 4 && (bytes.Equal(header[:4], []byte{0x00, 0x01, 0x00, 0x00}) || bytes.Equal(header[:4], []byte("true")) || bytes.Equal(header[:4], []byte("OTTO")))
	case ".pdf":
		return n >= 5 && bytes.Equal(header[:5], []byte("%PDF-"))
	default:
		return false
	}
}
