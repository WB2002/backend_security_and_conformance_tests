package httpclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var knownSuiteSlots = map[string]int{
	"00-harness-self-test":              1,
	"01-health-probes":                  10,
	"02-headers-cors-compression":       20,
	"03-validation-sanitization-errors": 30,
	"04-auth-sessions-csrf":             40,
	"05-rate-limiting":                  90,
	"06-feature-flags-rbac":             110,
	"07-graphql":                        120,
	"08-uploads":                        130,
	"09-websockets":                     140,
	"10-jobs-notifications-captcha":     160,
	"11-cache-resilience":               170,
	"12-http-client-resilience":         180,
	"13-overload-deadline-country":      190,
	"14-redaction-and-shutdown":         220,
	"15-destructive-shutdown":           235,
}

func fnv1aHash(input string) uint32 {
	var hash uint32 = 0x811c9dc5
	for i := 0; i < len(input); i++ {
		hash ^= uint32(input[i])
		hash *= 0x01000193
	}
	return hash
}

// ClientIPFor deterministically maps a suite name + index to an IPv4 address in the
// RFC 5737 TEST-NET-2 block (198.51.100.1 .. 198.51.100.250).
func ClientIPFor(suiteName string, index int) string {
	normalized := strings.TrimSuffix(suiteName, ".conformance.spec.ts")
	normalized = strings.TrimSuffix(normalized, ".spec.ts")

	baseSlot, ok := knownSuiteSlots[normalized]
	if !ok {
		baseSlot = int(fnv1aHash(normalized)%200) + 1
	}
	hostOctet := 1 + (((baseSlot-1+index)%250 + 250) % 250)
	return fmt.Sprintf("198.51.100.%d", hostOctet)
}

var (
	maxAgeZeroRe  = regexp.MustCompile(`(?i)max-age=0`)
	expires1970Re = regexp.MustCompile(`(?i)expires=thu,\s*01[- ]jan[- ]1970`)
)

type CookieJar struct {
	mu      sync.RWMutex
	cookies map[string]string
}

func NewCookieJar() *CookieJar {
	return &CookieJar{cookies: make(map[string]string)}
}

func (j *CookieJar) Set(name, value string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.cookies == nil {
		j.cookies = make(map[string]string)
	}
	j.cookies[name] = value
}

func (j *CookieJar) Get(name string) string {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.cookies[name]
}

func (j *CookieJar) Delete(name string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	delete(j.cookies, name)
}

func (j *CookieJar) Clear() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies = make(map[string]string)
}

func (j *CookieJar) ApplyTo(header http.Header) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	if len(j.cookies) == 0 {
		return
	}
	parts := make([]string, 0, len(j.cookies))
	for name, val := range j.cookies {
		parts = append(parts, fmt.Sprintf("%s=%s", name, val))
	}
	serialized := strings.Join(parts, "; ")
	if existing := header.Get("Cookie"); existing != "" {
		header.Set("Cookie", existing+"; "+serialized)
	} else {
		header.Set("Cookie", serialized)
	}
}

func (j *CookieJar) StoreFrom(resp *http.Response) {
	if resp == nil {
		return
	}
	rawSetCookies := resp.Header.Values("Set-Cookie")
	for _, rawHeader := range rawSetCookies {
		firstPair := strings.TrimSpace(strings.Split(rawHeader, ";")[0])
		if firstPair == "" {
			continue
		}
		eqIdx := strings.IndexByte(firstPair, '=')
		if eqIdx <= 0 {
			continue
		}
		name := strings.TrimSpace(firstPair[:eqIdx])
		value := strings.TrimSpace(firstPair[eqIdx+1:])
		if value == "" || maxAgeZeroRe.MatchString(rawHeader) || expires1970Re.MatchString(rawHeader) {
			j.Delete(name)
		} else {
			j.Set(name, value)
		}
	}
}

type RequestOptions struct {
	Headers     map[string]string
	JSONBody    any
	RawBody     []byte
	BearerToken string
	CSRF        bool
	ClientIP    string
}

type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

func (r *Response) JSON(target any) error {
	return json.Unmarshal(r.Body, target)
}

type ConformanceClient struct {
	Jar        *CookieJar
	ClientIP   string
	BaseURL    string
	HTTPClient *http.Client
}

func NewClient(suiteName string, baseURL string, ipIndex int) *ConformanceClient {
	return &ConformanceClient{
		Jar:      NewCookieJar(),
		ClientIP: ClientIPFor(suiteName, ipIndex),
		BaseURL:  strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *ConformanceClient) Request(method, path string, opts RequestOptions) (*Response, error) {
	var bodyReader io.Reader
	if opts.JSONBody != nil {
		b, err := json.Marshal(opts.JSONBody)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(b)
	} else if len(opts.RawBody) > 0 {
		bodyReader = bytes.NewReader(opts.RawBody)
	}

	targetURL := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		targetURL = c.BaseURL + path
	}

	req, err := http.NewRequest(method, targetURL, bodyReader)
	if err != nil {
		return nil, err
	}

	for k, v := range opts.Headers {
		req.Header.Set(k, v)
	}

	if req.Header.Get("X-Forwarded-For") == "" {
		ip := opts.ClientIP
		if ip == "" {
			ip = c.ClientIP
		}
		req.Header.Set("X-Forwarded-For", ip)
	}

	if opts.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+opts.BearerToken)
	}

	if c.Jar != nil {
		c.Jar.ApplyTo(req.Header)
		if opts.CSRF {
			if csrfTok := c.Jar.Get("csrf_token"); csrfTok != "" && req.Header.Get("X-CSRF-Token") == "" {
				req.Header.Set("X-CSRF-Token", csrfTok)
			}
		}
	}

	if opts.JSONBody != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if c.Jar != nil {
		c.Jar.StoreFrom(resp)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header.Clone(),
		Body:       respBytes,
	}, nil
}
