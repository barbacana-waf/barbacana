// Command rules fetches the pinned OWASP CRS release, installs its rule
// files into internal/protections/crs/rules/, regenerates curated-rules.conf
// from the curated subpackage source of truth, and installs the FTW
// regression-test corpus under tests/ftw/crs-tests/.
//
// Replaces scripts/fetch-crs.sh and scripts/extract-curated-rules.sh with
// a single Go entry point. All behavior uses the Go standard library — no
// external tools, no shell.
//
// Offline resilience: if a cached tarball at the expected path has the
// pinned SHA-256, download is skipped. If the cache miss coincides with a
// download failure, the tool exits with a clear error naming the remedy.
//
// Curated extraction is always re-run after rules are present so a change
// to the curated subpackage takes effect without requiring a re-download.
// Rule bodies are copied verbatim except for one mechanical rewrite:
// tx.inbound_anomaly_score_pl2/pl3 → pl1. Curated rules are promoted to
// always-on, so by definition their scores count at PL1.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/barbacana-waf/barbacana/internal/protections/crs/curated"
)

const (
	crsPkgDir          = "internal/protections/crs"
	rulesDir           = crsPkgDir + "/rules"
	curatedRequestOut  = rulesDir + "/curated-rules-request.conf"
	curatedResponseOut = rulesDir + "/curated-rules-response.conf"
	setupOut           = crsPkgDir + "/crs-setup.conf"
	ftwTestsDir        = "tests/ftw/crs-tests"
	shaFile            = "rules/CRS_SHA256"
	versionsMk         = "versions.mk"
	cacheDir           = ".cache/crs"
)

func main() {
	var skipFTW bool
	flag.BoolVar(&skipFTW, "skip-ftw", false, "skip installing the FTW regression test corpus")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log, skipFTW); err != nil {
		log.Error("rules tool failed", "err", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger, skipFTW bool) error {
	version, err := readCRSVersion(versionsMk)
	if err != nil {
		return fmt.Errorf("read CRS version: %w", err)
	}
	expectedSHA, err := readCheckum(shaFile)
	if err != nil {
		return fmt.Errorf("read pinned SHA-256: %w", err)
	}
	log.Info("CRS tooling start", "version", version, "pinned_sha256", expectedSHA)

	tarballPath, err := ensureTarball(log, version, expectedSHA)
	if err != nil {
		return err
	}

	if err := installRules(log, tarballPath); err != nil {
		return fmt.Errorf("install CRS rules: %w", err)
	}

	if err := writeCuratedRules(log, version); err != nil {
		return fmt.Errorf("regenerate curated-rules.conf: %w", err)
	}

	if !skipFTW {
		if err := installFTWCorpus(log, tarballPath); err != nil {
			return fmt.Errorf("install FTW test corpus: %w", err)
		}
	}
	log.Info("done")
	return nil
}

// readCRSVersion extracts CRS_VERSION=... from versions.mk.
func readCRSVersion(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if v, ok := strings.CutPrefix(line, "CRS_VERSION="); ok {
			return strings.TrimSpace(v), nil
		}
	}
	return "", fmt.Errorf("CRS_VERSION not found in %s", path)
}

// readCheckum reads the first whitespace-separated token from shaFile.
// Matches the format produced by `sha256sum` / `shasum -a 256`.
func readCheckum(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return "", fmt.Errorf("%s is empty", path)
	}
	return strings.ToLower(fields[0]), nil
}

// ensureTarball returns a path to a verified CRS release tarball. Uses
// a cached copy if its SHA-256 matches the pinned checksum; otherwise
// downloads and caches. A download failure is only fatal when no cache
// entry is available.
func ensureTarball(log *slog.Logger, version, expectedSHA string) (string, error) {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("create cache dir: %w", err)
	}
	path := filepath.Join(cacheDir, "crs-"+version+".tar.gz")

	if sum, err := sha256File(path); err == nil {
		if sum == expectedSHA {
			log.Info("CRS tarball cache hit, skipping download", "path", path)
			return path, nil
		}
		log.Warn("cached CRS tarball checksum mismatch, re-downloading",
			"path", path, "got", sum, "want", expectedSHA)
	}

	url := fmt.Sprintf("https://github.com/coreruleset/coreruleset/archive/refs/tags/%s.tar.gz", version)
	log.Info("downloading CRS release", "url", url)
	if err := downloadFile(url, path); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("CRS download failed — run 'make rules' with internet access to populate %s: %w", path, err)
	}
	sum, err := sha256File(path)
	if err != nil {
		return "", fmt.Errorf("hash downloaded tarball: %w", err)
	}
	if sum != expectedSHA {
		return "", fmt.Errorf("CRS tarball checksum mismatch: got %s, pinned %s (update %s after verifying)", sum, expectedSHA, shaFile)
	}
	return path, nil
}

func downloadFile(url, dest string) error {
	client := &http.Client{Timeout: 2 * time.Minute}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// installRules extracts rule files (*.conf, *.data) and crs-setup.conf.example
// from the tarball into the embed package. Clears rulesDir first so removed
// upstream files are not left stale.
func installRules(log *slog.Logger, tarballPath string) error {
	if err := os.RemoveAll(rulesDir); err != nil {
		return err
	}
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		return err
	}

	wrote := 0
	err := walkTarball(tarballPath, func(name string, body []byte) error {
		// Path inside the archive looks like:
		//   coreruleset-4.25.0/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf
		//   coreruleset-4.25.0/crs-setup.conf.example
		rel := stripFirstPathComponent(name)
		switch {
		case rel == "crs-setup.conf.example":
			return os.WriteFile(setupOut, body, 0o644)
		case strings.HasPrefix(rel, "rules/") && (strings.HasSuffix(rel, ".conf") || strings.HasSuffix(rel, ".data")):
			out := filepath.Join(rulesDir, filepath.Base(rel))
			if err := os.WriteFile(out, body, 0o644); err != nil {
				return err
			}
			wrote++
			return nil
		}
		return nil
	})
	if err != nil {
		return err
	}
	log.Info("CRS rules installed", "dir", rulesDir, "files", wrote)
	return nil
}

// installFTWCorpus extracts the CRS regression test corpus used by the
// nightly go-ftw security workflow.
func installFTWCorpus(log *slog.Logger, tarballPath string) error {
	if err := os.RemoveAll(ftwTestsDir); err != nil {
		return err
	}
	if err := os.MkdirAll(ftwTestsDir, 0o755); err != nil {
		return err
	}
	wrote := 0
	err := walkTarball(tarballPath, func(name string, body []byte) error {
		rel := stripFirstPathComponent(name)
		const prefix = "tests/regression/tests/"
		if !strings.HasPrefix(rel, prefix) {
			return nil
		}
		out := filepath.Join(ftwTestsDir, strings.TrimPrefix(rel, prefix))
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(out, body, 0o644); err != nil {
			return err
		}
		wrote++
		return nil
	})
	if err != nil {
		return err
	}
	log.Info("FTW test corpus installed", "dir", ftwTestsDir, "files", wrote)
	return nil
}

// walkTarball opens a .tar.gz and invokes visit for each regular file
// with its archive-relative name and full body.
func walkTarball(path string, visit func(name string, body []byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return err
		}
		if err := visit(hdr.Name, body); err != nil {
			return err
		}
	}
}

func stripFirstPathComponent(p string) string {
	if i := strings.Index(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// writeCuratedRules is the Go port of scripts/extract-curated-rules.sh
// with the pl2/pl3 → pl1 score rewrite documented in
// docs/design/security-evaluation.md.
//
// Extraction reads the installed CRS *.conf files and splices out the
// full SecRule block for each ID in curated.Rules. A block begins at a
// column-0 "SecRule " line and runs until the next blank line or the
// next column-0 "SecRule " — this keeps chain starters together with
// their indented chained continuations, which Coraza requires to parse.
func writeCuratedRules(log *slog.Logger, version string) error {
	// Group IDs by source file so we read each file once.
	idsByFile := map[string][]int{}
	for _, r := range curated.Rules {
		src, err := sourceFileForID(r.ID)
		if err != nil {
			return err
		}
		idsByFile[src] = append(idsByFile[src], r.ID)
	}

	// Accumulate extracted blocks in curated.Rules order so the generated
	// file is stable across runs.
	extracted := make(map[int]string, len(curated.Rules))
	for src, ids := range idsByFile {
		full := filepath.Join(rulesDir, src)
		data, err := os.ReadFile(full)
		if err != nil {
			return fmt.Errorf("read %s: %w", full, err)
		}
		blocks := extractSecRuleBlocks(string(data), ids)
		for id, block := range blocks {
			extracted[id] = block
		}
	}
	for _, r := range curated.Rules {
		if _, ok := extracted[r.ID]; !ok {
			return fmt.Errorf("curated rule %d not found in %s — CRS %s may have removed or renumbered it; update internal/protections/crs/curated", r.ID, filepath.Join(rulesDir, mustSourceFile(r.ID)), version)
		}
	}

	// Split by phase. Request-phase curated rules must load before
	// REQUEST-949-BLOCKING-EVALUATION; response-phase rules must load
	// before RESPONSE-959. Loading them all in one file would force the
	// response originals' IDs to collide with the curated copies, since
	// SecRuleRemoveById can only remove already-loaded rules and the
	// originals haven't loaded yet at the request-phase emission point.
	// The split mirrors that constraint.
	var requestRules, responseRules []curated.Rule
	for _, r := range curated.Rules {
		if isResponsePhaseRule(r.ID) {
			responseRules = append(responseRules, r)
		} else {
			requestRules = append(requestRules, r)
		}
	}

	if err := writeCuratedFile(curatedRequestOut, "request", "REQUEST-949-BLOCKING-EVALUATION.conf", version, extracted, requestRules); err != nil {
		return err
	}
	if err := writeCuratedFile(curatedResponseOut, "response", "RESPONSE-959-BLOCKING-EVALUATION.conf", version, extracted, responseRules); err != nil {
		return err
	}
	log.Info("curated rules written",
		"request_path", curatedRequestOut, "request_rules", len(requestRules),
		"response_path", curatedResponseOut, "response_rules", len(responseRules))
	return nil
}

// isResponsePhaseRule reports whether the curated rule belongs to a
// RESPONSE-* CRS source file. The phase determines which curated-rules-
// {request,response}.conf file the body is emitted to.
func isResponsePhaseRule(id int) bool {
	src, err := sourceFileForID(id)
	if err != nil {
		return false
	}
	return strings.HasPrefix(src, "RESPONSE-")
}

func writeCuratedFile(path, phase, blockingMarker, version string, extracted map[int]string, rules []curated.Rule) error {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# Auto-generated by cmd/tools/rules — do not edit by hand.\n")
	fmt.Fprintf(&buf, "# Curated %s-phase rules force-enabled by Barbacana on top of the\n", phase)
	fmt.Fprintf(&buf, "# PL1 baseline. Source: OWASP CRS %s.\n", version)
	fmt.Fprintf(&buf, "#\n")
	fmt.Fprintf(&buf, "# The CRS originals are stripped with SecRuleRemoveById before this\n")
	fmt.Fprintf(&buf, "# file loads, so the IDs remain unique. This file is loaded BEFORE\n")
	fmt.Fprintf(&buf, "# %s so matches can influence the\n", blockingMarker)
	fmt.Fprintf(&buf, "# blocking anomaly score.\n")
	fmt.Fprintf(&buf, "#\n")
	fmt.Fprintf(&buf, "# Score accumulators for higher paranoia levels are rewritten to the\n")
	fmt.Fprintf(&buf, "# PL1 accumulator and NOTICE/WARNING/ERROR severities to CRITICAL.\n")
	fmt.Fprintf(&buf, "# Curation expresses an act-on intent — see\n")
	fmt.Fprintf(&buf, "# docs/design/security-evaluation.md and the comment block on\n")
	fmt.Fprintf(&buf, "# rewriteScoreAccumulators in cmd/tools/rules.\n\n")

	for _, r := range rules {
		body := rewriteScoreAccumulators(extracted[r.ID])
		if r.Severity != "" {
			b, err := applySeverityOverride(body, r)
			if err != nil {
				return fmt.Errorf("apply severity override on rule %d: %w", r.ID, err)
			}
			body = b
		}
		buf.WriteString(body)
		if !strings.HasSuffix(body, "\n\n") {
			buf.WriteString("\n")
		}
	}

	if len(rules) == 0 {
		buf.WriteString("# (empty — no curated rules in this phase)\n")
	}

	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// scoreAccumulatorRewrite rewrites higher-paranoia accumulator names
// so curated rule scores land in the PL1 bucket where the configured
// paranoia level reads them. Symmetric for inbound (request phase) and
// outbound (response phase) — RESPONSE-950 / RESPONSE-956 / etc. write
// to outbound_anomaly_score_pl2 by default and need the same flattening.
var scoreAccumulatorRewrite = regexp.MustCompile(`tx\.(inbound|outbound)_anomaly_score_pl[234]=`)

func rewriteScoreAccumulators(s string) string {
	return scoreAccumulatorRewrite.ReplaceAllString(s, "tx.${1}_anomaly_score_pl1=")
}

// allowedSeverities is the closed set of CRS severity tokens. Per-rule
// overrides outside this set are rejected at extraction time so a typo
// can't silently miscategorize a rule.
var allowedSeverities = map[string]bool{
	"CRITICAL": true,
	"ERROR":    true,
	"WARNING":  true,
	"NOTICE":   true,
}

// severityScoreSource maps a severity token to the matching CRS tx
// score variable. Used by applySeverityOverride to retarget every
// `tx.<old>_anomaly_score` reference inside the rule body to the
// override's score variable, plus the `severity:'<X>'` declaration line
// itself.
var severityScoreSource = map[string]string{
	"CRITICAL": "tx.critical_anomaly_score",
	"ERROR":    "tx.error_anomaly_score",
	"WARNING":  "tx.warning_anomaly_score",
	"NOTICE":   "tx.notice_anomaly_score",
}

var anySeverityScore = regexp.MustCompile(`tx\.(critical|error|warning|notice)_anomaly_score`)

// applySeverityOverride rewrites a rule body to declare the override
// severity and source its score from the matching tx variable. Returns
// the rewritten body unchanged if the rule already authored at the
// override severity (no-op promotion).
//
// Curation expresses an act-on intent: a rule selected by hand for
// force-enablement at PL1, or for opt-in PL1 enablement via the
// `enable:` list, is by construction "operator opted to treat this
// match as actionable." A CRS NOTICE rule (score 2) never crosses the
// blocking threshold (5) on its own match, so without this rewrite a
// curated NOTICE rule cannot block end-to-end and the `enable:` lever
// is dead for the leaves backed by it. The override is recorded
// per-rule on curated.Rule.Severity so the security trade-off lives
// next to the entry it applies to. See docs/design/security-evaluation.md.
func applySeverityOverride(body string, r curated.Rule) (string, error) {
	if !allowedSeverities[r.Severity] {
		return "", fmt.Errorf("severity %q not in allowed set (CRITICAL|ERROR|WARNING|NOTICE)", r.Severity)
	}
	target := severityScoreSource[r.Severity]

	// Replace severity:'<X>' with the override. CRS rules quote the
	// token with single quotes; match either case for safety.
	sevDecl := regexp.MustCompile(`severity:'[A-Z]+'`)
	body = sevDecl.ReplaceAllString(body, "severity:'"+r.Severity+"'")

	// Retarget every score-source reference to the override's tx
	// variable. Catches both the score-bucket setvars
	// (`tx.<X>_anomaly_score_pl1=+%{tx.<sev>_anomaly_score}`) and the
	// per-attack-class setvars (`tx.sql_injection_score=+%{tx.<sev>_anomaly_score}`).
	body = anySeverityScore.ReplaceAllString(body, target)
	return body, nil
}

// sourceFileForID returns the canonical CRS filename that hosts the rule
// ID, based on the three-digit prefix convention CRS uses.
func sourceFileForID(id int) (string, error) {
	prefix := id / 1000
	switch prefix {
	case 920:
		return "REQUEST-920-PROTOCOL-ENFORCEMENT.conf", nil
	case 921:
		return "REQUEST-921-PROTOCOL-ATTACK.conf", nil
	case 931:
		return "REQUEST-931-APPLICATION-ATTACK-RFI.conf", nil
	case 932:
		return "REQUEST-932-APPLICATION-ATTACK-RCE.conf", nil
	case 933:
		return "REQUEST-933-APPLICATION-ATTACK-PHP.conf", nil
	case 934:
		return "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf", nil
	case 941:
		return "REQUEST-941-APPLICATION-ATTACK-XSS.conf", nil
	case 942:
		return "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", nil
	case 944:
		return "REQUEST-944-APPLICATION-ATTACK-JAVA.conf", nil
	case 950:
		return "RESPONSE-950-DATA-LEAKAGES.conf", nil
	case 956:
		return "RESPONSE-956-DATA-LEAKAGES-RUBY.conf", nil
	default:
		return "", fmt.Errorf("no CRS source file known for rule prefix %d (id %d) — extend sourceFileForID", prefix, id)
	}
}

// mustSourceFile is sourceFileForID for use in error-message formatting
// where the caller has already validated the ID.
func mustSourceFile(id int) string {
	s, err := sourceFileForID(id)
	if err != nil {
		return "<unknown>"
	}
	return s
}

// extractSecRuleBlocks scans a CRS .conf and returns the raw text of the
// full SecRule block for each requested ID. A block starts at a line
// matching ^SecRule and ends at the next blank line or the next ^SecRule.
// Chained rules (SecRule starters followed by indented SecRule
// continuations) are kept in one block because subsequent SecRule lines
// are indented, not column-0.
func extractSecRuleBlocks(content string, wantIDs []int) map[int]string {
	want := make(map[int]bool, len(wantIDs))
	for _, id := range wantIDs {
		want[id] = true
	}
	out := make(map[int]string, len(wantIDs))

	lines := strings.Split(content, "\n")
	i := 0
	secRuleStart := regexp.MustCompile(`^SecRule\s`)
	idRegex := regexp.MustCompile(`id:(\d+)`)

	for i < len(lines) {
		if !secRuleStart.MatchString(lines[i]) {
			i++
			continue
		}
		start := i
		i++
		for i < len(lines) {
			line := lines[i]
			if strings.TrimSpace(line) == "" {
				break
			}
			if secRuleStart.MatchString(line) {
				break
			}
			i++
		}
		block := strings.Join(lines[start:i], "\n")
		if m := idRegex.FindStringSubmatch(block); m != nil {
			id, _ := strconv.Atoi(m[1])
			if want[id] {
				out[id] = block + "\n"
			}
		}
	}
	return out
}

