package vuln

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const EPSSURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
const KEVURL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"

const (
	maxEPSSCompressed   = 32 << 20
	maxEPSSDecompressed = 128 << 20
	maxEPSSLine         = 4096
	maxKEVBytes         = 16 << 20
	maxFeedAge          = 48 * time.Hour
	fetchTimeout        = 20 * time.Second
	maxRedirects        = 2
)

// EPSSFeed is a validated publication with explicit source/retrieval metadata.
// Scores are caller-owned. Check Fresh before passing them to Prioritize.
type EPSSFeed struct {
	Scores      map[string]float64
	Published   time.Time
	Model       string
	RetrievedAt time.Time
	Source      string
	SHA256      string // of the bytes as received (gzip)
}

// KEVFeed records the official publisher mirror provenance, not CISA SLA policy.
type KEVFeed struct {
	CVEs           map[string]bool
	CatalogVersion string
	DateReleased   time.Time
	Count          int
	RetrievedAt    time.Time
	Source         string
	SHA256         string
}

// capReader fails once more than max bytes have been read.
type capReader struct {
	r    io.Reader
	n    int64
	max  int64
	what string
}

func (c *capReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		return n, fmt.Errorf("%s exceeds %d-byte limit", c.what, c.max)
	}
	return n, err
}

func checkProvenance(r io.Reader, source, want string, retrieved time.Time) error {
	switch {
	case r == nil:
		return errors.New("vuln: nil reader")
	case source != want:
		return fmt.Errorf("vuln: source %q is not the official feed %q", source, want)
	case retrieved.IsZero():
		return errors.New("vuln: zero retrieval time")
	}
	return nil
}

func parseScoreDate(s string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02", time.RFC3339Nano, "2006-01-02T15:04:05-0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable score_date %q", s)
}

func ParseEPSS(r io.Reader, source string, retrieved time.Time) (EPSSFeed, error) {
	if err := checkProvenance(r, source, EPSSURL, retrieved); err != nil {
		return EPSSFeed{}, err
	}
	sum := sha256.New()
	raw := io.TeeReader(&capReader{r: r, max: maxEPSSCompressed, what: "EPSS download"}, sum)
	z, err := gzip.NewReader(raw)
	if err != nil {
		return EPSSFeed{}, fmt.Errorf("EPSS gzip: %w", err)
	}
	defer z.Close()
	f, err := parseEPSSCSV(&capReader{r: z, max: maxEPSSDecompressed, what: "EPSS CSV"}, retrieved)
	if err != nil {
		return EPSSFeed{}, err
	}
	f.Source, f.RetrievedAt, f.SHA256 = source, retrieved, hexSum(sum)
	return f, nil
}

func parseEPSSCSV(r io.Reader, retrieved time.Time) (EPSSFeed, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, maxEPSSLine), maxEPSSLine)
	line, lineNo := "", 0
	next := func() bool {
		if !sc.Scan() {
			return false
		}
		lineNo++
		line = strings.TrimSuffix(sc.Text(), "\r")
		return true
	}
	fail := func(format string, a ...any) (EPSSFeed, error) {
		return EPSSFeed{}, fmt.Errorf("EPSS line %d: %s", lineNo, fmt.Sprintf(format, a...))
	}
	scanErr := func() (EPSSFeed, error) {
		if err := sc.Err(); err != nil {
			return EPSSFeed{}, fmt.Errorf("EPSS read: %w", err)
		}
		return fail("unexpected end of file")
	}

	var f EPSSFeed
	if !next() {
		return scanErr()
	}
	meta := strings.TrimPrefix(line, "\xef\xbb\xbf") // UTF-8 BOM
	if !strings.HasPrefix(meta, "#") {
		return fail("missing #model_version/score_date comment")
	}
	kv := map[string]string{}
	for _, part := range strings.Split(meta[1:], ",") {
		k, v, ok := strings.Cut(part, ":")
		if !ok || kv[k] != "" {
			return fail("malformed or duplicate metadata %q", part)
		}
		kv[k] = v
	}
	f.Model = kv["model_version"]
	if f.Model == "" {
		return fail("missing model_version")
	}
	pub, err := parseScoreDate(kv["score_date"])
	if err != nil {
		return fail("%v", err)
	}
	if pub.After(retrieved) {
		return fail("score_date %s is after retrieval %s", pub, retrieved)
	}
	f.Published = pub

	if !next() {
		return scanErr()
	}
	col := map[string]int{}
	header := strings.Split(line, ",")
	for i, name := range header {
		if _, dup := col[name]; dup {
			return fail("duplicate column %q", name)
		}
		col[name] = i
	}
	for _, name := range []string{"cve", "epss", "percentile"} {
		if _, ok := col[name]; !ok {
			return fail("missing column %q", name)
		}
	}

	f.Scores = map[string]float64{}
	for next() {
		fields := strings.Split(line, ",")
		if len(fields) != len(header) {
			return fail("want %d fields, got %d", len(header), len(fields))
		}
		cve := fields[col["cve"]]
		if !validCVE(cve) {
			return fail("malformed CVE %q", cve)
		}
		if _, dup := f.Scores[cve]; dup {
			return fail("duplicate CVE %s", cve)
		}
		p, err := strconv.ParseFloat(fields[col["epss"]], 64)
		if err != nil || !validProbability(p) {
			return fail("epss %q outside [0,1]", fields[col["epss"]])
		}
		pct, err := strconv.ParseFloat(fields[col["percentile"]], 64)
		if err != nil || !validProbability(pct) {
			return fail("percentile %q outside [0,1]", fields[col["percentile"]])
		}
		f.Scores[cve] = p
	}
	if err := sc.Err(); err != nil {
		return EPSSFeed{}, fmt.Errorf("EPSS read after line %d: %w", lineNo, err)
	}
	if len(f.Scores) == 0 {
		return EPSSFeed{}, errors.New("EPSS publication has no scores")
	}
	return f, nil
}

type kevDoc struct {
	CatalogVersion  *string      `json:"catalogVersion"`
	DateReleased    *string      `json:"dateReleased"`
	Count           *json.Number `json:"count"`
	Vulnerabilities *[]kevEntry  `json:"vulnerabilities"`
}

type kevEntry struct {
	CVEID             *string `json:"cveID"`
	VendorProject     *string `json:"vendorProject"`
	Product           *string `json:"product"`
	VulnerabilityName *string `json:"vulnerabilityName"`
	DateAdded         *string `json:"dateAdded"`
	ShortDescription  *string `json:"shortDescription"`
	RequiredAction    *string `json:"requiredAction"`
	DueDate           *string `json:"dueDate"`
}

func (e kevEntry) required() []*string {
	return []*string{e.CVEID, e.VendorProject, e.Product, e.VulnerabilityName,
		e.DateAdded, e.ShortDescription, e.RequiredAction, e.DueDate}
}

func ParseKEV(r io.Reader, source string, retrieved time.Time) (KEVFeed, error) {
	if err := checkProvenance(r, source, KEVURL, retrieved); err != nil {
		return KEVFeed{}, err
	}
	raw, err := io.ReadAll(&capReader{r: r, max: maxKEVBytes, what: "KEV JSON"})
	if err != nil {
		return KEVFeed{}, err
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return KEVFeed{}, fmt.Errorf("KEV JSON: %w", err)
	}
	var doc kevDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return KEVFeed{}, fmt.Errorf("KEV JSON: %w", err)
	}
	if doc.CatalogVersion == nil || *doc.CatalogVersion == "" || doc.DateReleased == nil ||
		doc.Count == nil || doc.Vulnerabilities == nil {
		return KEVFeed{}, errors.New("KEV: missing catalogVersion, dateReleased, count or vulnerabilities")
	}
	released, err := time.Parse(time.RFC3339Nano, *doc.DateReleased)
	if err != nil {
		return KEVFeed{}, fmt.Errorf("KEV dateReleased: %w", err)
	}
	if released.After(retrieved) {
		return KEVFeed{}, fmt.Errorf("KEV dateReleased %s is after retrieval %s", released, retrieved)
	}
	count, err := strconv.Atoi(doc.Count.String())
	if err != nil || count != len(*doc.Vulnerabilities) {
		return KEVFeed{}, fmt.Errorf("KEV count %s does not match %d entries", doc.Count, len(*doc.Vulnerabilities))
	}
	f := KEVFeed{CVEs: make(map[string]bool, count), CatalogVersion: *doc.CatalogVersion,
		DateReleased: released.UTC(), Count: count, RetrievedAt: retrieved, Source: source}
	for i, e := range *doc.Vulnerabilities {
		for _, field := range e.required() {
			if field == nil {
				return KEVFeed{}, fmt.Errorf("KEV entry %d: missing required field", i)
			}
		}
		cve := *e.CVEID
		if !validCVE(cve) {
			return KEVFeed{}, fmt.Errorf("KEV entry %d: malformed CVE %q", i, cve)
		}
		if f.CVEs[cve] {
			return KEVFeed{}, fmt.Errorf("KEV: duplicate CVE %s", cve)
		}
		added, err1 := time.Parse("2006-01-02", *e.DateAdded)
		due, err2 := time.Parse("2006-01-02", *e.DueDate)
		switch {
		case err1 != nil || err2 != nil:
			return KEVFeed{}, fmt.Errorf("KEV %s: invalid dateAdded/dueDate", cve)
		case due.Before(added):
			return KEVFeed{}, fmt.Errorf("KEV %s: dueDate before dateAdded", cve)
		case added.After(released):
			return KEVFeed{}, fmt.Errorf("KEV %s: dateAdded after catalog release", cve)
		}
		f.CVEs[cve] = true
	}
	sum := sha256.Sum256(raw)
	f.SHA256 = hex.EncodeToString(sum[:])
	return f, nil
}

// rejectDuplicateKeys walks the token stream; encoding/json silently keeps the
// last duplicate, which would let a crafted catalog hide a field.
func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'):
			keys := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return err
				}
				key := k.(string)
				if keys[key] {
					return fmt.Errorf("duplicate key %q", key)
				}
				keys[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case json.Delim('['):
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

func hexSum(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }

func checkAge(what string, t, now time.Time) error {
	switch {
	case t.IsZero():
		return fmt.Errorf("%s time missing", what)
	case t.After(now):
		return fmt.Errorf("%s %s is in the future", what, t)
	case now.Sub(t) > maxFeedAge:
		return fmt.Errorf("%s %s is older than %s", what, t, maxFeedAge)
	}
	return nil
}

// Fresh requires both a recent retrieval and a recent daily publication.
func (f EPSSFeed) Fresh(now time.Time) error {
	if err := checkAge("EPSS retrieval", f.RetrievedAt, now); err != nil {
		return err
	}
	return checkAge("EPSS publication", f.Published, now)
}

// Fresh only bounds retrieval age: the catalog changes when CISA adds entries,
// so an old dateReleased is current as long as it was fetched recently.
func (f KEVFeed) Fresh(now time.Time) error {
	if f.DateReleased.After(now) {
		return fmt.Errorf("KEV dateReleased %s is in the future", f.DateReleased)
	}
	return checkAge("KEV retrieval", f.RetrievedAt, now)
}

func FetchEPSS(ctx context.Context) (EPSSFeed, error) {
	return fetchEPSS(ctx, http.DefaultTransport, time.Now)
}

func FetchKEV(ctx context.Context) (KEVFeed, error) {
	return fetchKEV(ctx, http.DefaultTransport, time.Now)
}

func fetchEPSS(ctx context.Context, transport http.RoundTripper, now func() time.Time) (EPSSFeed, error) {
	var f EPSSFeed
	err := fetch(ctx, transport, EPSSURL, func(body io.Reader) error {
		at := now().UTC()
		var err error
		if f, err = ParseEPSS(body, EPSSURL, at); err != nil {
			return err
		}
		return f.Fresh(at)
	})
	if err != nil {
		return EPSSFeed{}, err
	}
	return f, nil
}

func fetchKEV(ctx context.Context, transport http.RoundTripper, now func() time.Time) (KEVFeed, error) {
	var f KEVFeed
	err := fetch(ctx, transport, KEVURL, func(body io.Reader) error {
		at := now().UTC()
		var err error
		if f, err = ParseKEV(body, KEVURL, at); err != nil {
			return err
		}
		return f.Fresh(at)
	})
	if err != nil {
		return KEVFeed{}, err
	}
	return f, nil
}

// fetch makes one anonymous, time-bounded GET. Redirects must stay on https
// and the same host, carry no credentials and never revisit a URL.
func fetch(ctx context.Context, transport http.RoundTripper, rawURL string, parse func(io.Reader) error) error {
	if ctx == nil || transport == nil {
		return errors.New("vuln: nil context or transport")
	}
	origin, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	client := &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		u := req.URL
		if len(via) > maxRedirects {
			return errors.New("too many redirects")
		}
		if u.Scheme != "https" || u.Host != origin.Host || u.User != nil {
			return fmt.Errorf("redirect to %s leaves %s", u.Redacted(), origin.Host)
		}
		for _, v := range via {
			if v.URL.String() == u.String() {
				return fmt.Errorf("redirect loop at %s", u)
			}
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	return parse(resp.Body)
}
