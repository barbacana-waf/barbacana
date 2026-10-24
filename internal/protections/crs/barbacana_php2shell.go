package crs

// barbacanaPHP2ShellRules is a Barbacana-owned Coraza SecRule that blocks
// the request vector of CVE-2026-109619 ("PHP2Shell", advisory
// GHSA-6wmf-4rv5-p3rp): a POST body carrying PHP's session upload-progress
// marker field, PHP_SESSION_UPLOAD_PROGRESS (the default value of
// session.upload_progress.name). PHP consumes that field during multipart
// parsing, before normal session/request initialisation and without the
// application ever calling session_start(). PHP's own manual separately
// warns that the field and file names it records are unvalidated and "may
// contain PHP code, making any local file inclusion vulnerability trivial
// to exploit" — so the field is dangerous even on patched engines unless
// the application deliberately uses upload-progress tracking.
//
// A match means the request has the attack's shape, not that exploitation
// occurred. Patching PHP remains the fix; this rule only removes the
// unauthenticated entry point at the edge.
//
// Design notes:
//
//   - ID 211001, in the 211000 range reserved for Barbacana custom PHP
//     rules. See the custom-ID registry next to the injection point in
//     NewEngine (crs.go) before picking IDs for a new custom rule.
//   - POST only. PHP runs the upload-progress hook from its RFC 1867
//     (multipart/form-data) POST handler; a GET carrying the same token
//     cannot reach it, so the method gate keeps the rule from firing on
//     unrelated query strings. The comparison is case-sensitive; that PHP
//     matches the field name exactly (no case folding, no decoding of
//     RFC 2047 encoded-word names) has not been verified against php-src,
//     so a lower-case or encoded variant may still reach PHP.
//   - No PHPSESSID requirement. php-src (ext/session/session.c) resolves
//     the session ID from a cookie, the query string, or a same-named form
//     field, so requiring a PHPSESSID cookie would be a trivial bypass.
//   - Surfaces inspected, all with t:none (a field-name match needs no
//     decoding; Coraza has already URL-decoded urlencoded names):
//     ARGS_NAMES covers urlencoded and multipart field names;
//     FILES_NAMES and MULTIPART_NAME cover a part sent with a filename
//     (Coraza files it as an upload, not an ARG, and a backend with
//     different filename precedence may still treat it as a field);
//     MULTIPART_PART_HEADERS covers the raw Content-Disposition line when
//     Coraza's parser cannot extract a form name; REQUEST_BODY covers a
//     multipart body sent under a Content-Type Coraza does not classify as
//     multipart (CRS 901340 then forces the raw body into REQUEST_BODY).
//     @contains is used rather than an exact match so decorated names
//     (e.g. a trailing "[]") still match. The REQUEST_BODY fallback is a
//     substring match on the raw body, so a legitimate POST that merely
//     quotes the token (a support ticket, a security write-up) is blocked
//     too; routes that need that disable the leaf.
//   - severity:CRITICAL and adds the critical score to both the CRS PHP
//     category accumulator (tx.php_injection_score) and the inbound PL1
//     anomaly score, so a single match meets the blocking threshold.
//
// Mapped to the catalog leaf `php-php2shell-session-upload-progress`. Disabling the leaf
// emits SecRuleRemoveById 211001 via the standard mechanism.
const barbacanaPHP2ShellRules = `
SecRule REQUEST_METHOD "@streq POST" \
    "id:211001,\
    phase:2,\
    block,\
    t:none,\
    msg:'PHP2Shell (CVE-2026-109619) request vector: PHP_SESSION_UPLOAD_PROGRESS field in POST body (vector match, not proof of exploitation)',\
    logdata:'Matched Data: PHP_SESSION_UPLOAD_PROGRESS found within %{MATCHED_VAR_NAME}',\
    tag:'application-multi',\
    tag:'language-php',\
    tag:'platform-multi',\
    tag:'attack-rce',\
    tag:'barbacana-custom',\
    severity:'CRITICAL',\
    chain"
    SecRule ARGS_NAMES|FILES_NAMES|MULTIPART_NAME|MULTIPART_PART_HEADERS|REQUEST_BODY "@contains PHP_SESSION_UPLOAD_PROGRESS" \
        "t:none,\
        setvar:'tx.php_injection_score=+%{tx.critical_anomaly_score}',\
        setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
`

// barbacanaPHP2ShellMultipartRules are Barbacana-owned Coraza SecRules that cap
// the multipart request shapes behind CVE-2026-109618 (advisory
// GHSA-w8hw-w9fx-j79w, part of the "PHP2Shell" disclosure). The PHP bug is
// memory corruption: an out-of-memory during request startup leaves
// request state half-initialised, and shutdown later reads it
// (CWE-416/824). The advisory names two ways a request well under any
// byte-size cap can still exhaust PHP's memory_limit:
//
//   - a single multipart part can carry an unbounded number of headers,
//     and PHP's in-memory representation of them is far larger than the
//     wire bytes; and
//   - empty file controls (filename="") do not count toward PHP's
//     max_file_uploads but still allocate $_FILES metadata arrays, and
//     nested field names multiply that allocation.
//
// Byte limits cannot express either shape, so these rules count parts and
// headers. A match means the request has the attack's shape, not that
// exploitation occurred. Patching PHP remains the fix.
//
// What Coraza v3.8.1 actually exposes (observed with a probe that sent 10
// plain fields, 3 named uploads, and 2 empty file controls named
// "emptyN[a][b]", then dumped every populated collection):
//
//   - Plain fields go to ARGS/ARGS_POST/ARGS_NAMES (10 entries).
//   - Named uploads go to FILES/FILES_NAMES/MULTIPART_FILENAME (3) and not
//     to ARGS.
//   - Empty file controls are NOT dropped (unlike Barbacana's native
//     validator, which skips parts with no filename when counting files).
//     Coraza treats filename="" as "no filename" and files the part as a
//     field: it appears in ARGS with an empty value (ARGS = 12), never in
//     FILES/FILES_NAMES (= 3), and nothing marks it as an empty file
//     control except its raw Content-Disposition line.
//   - MULTIPART_NAME gets one entry per part of any kind (= 15), and
//     MULTIPART_PART_HEADERS gets one entry per header line per part
//     (= 20: 10x1 + 3x2 + 2x2). Repeated header names are all kept.
//   - The &COLLECTION count idiom (the same one CRS 920380 uses as
//     &ARGS "@gt N") works on both.
//   - Coraza runs non-disruptive actions (setvar) once per matched value,
//     including in a chain link whose next link then fails. That lets
//     rule 212003 count matching part headers but log a match only when
//     the count passes its limit.
//   - Coraza parses parts with Go's mime/multipart, which refuses a part
//     whose header block has more than 10,000 entries (or more than 10MB of
//     header memory) with "multipart: message too large". Parsing then
//     stops. MULTIPART_PART_HEADERS is left empty and REQBODY_ERROR=1, so
//     a header count alone never sees the most extreme flood. Rule 212002
//     closes that gap. No CRS rule loaded by Barbacana checks
//     REQBODY_ERROR, so without 212002 such a body would pass with the
//     rest of it unparsed.
//
// Scope limits (inherent to where these rules run, not bugs in them):
//
//   - Coraza only sees max_inspect_size bytes of the body (route
//     inspection.max_inspect_size, default 128KB), and what counts toward
//     that is what the rules read: for a multipart body the contents of
//     uploaded files are left out (see multipart_projection.go) while every
//     part header and non-file field is kept. So a large upload with a
//     small form around it is inspected in full, and these rules see every
//     part header whatever the upload weighs. A body whose non-file content
//     alone overflows the window follows inspection.on_oversize: rejected
//     with 413 by default, so that in blocking mode these rules always see
//     the whole of any request that gets through; with inspect_prefix they
//     see only the first window. A part header block too large for Go's
//     parser inside such a body is blocked directly under the part-headers
//     leaf (the condition rule 212002 matches). In detect_only mode Coraza
//     forces ProcessPartial: rules see only the first window, and a part
//     whose header block is cut off by the window is not counted (Go
//     reports a malformed header or a clean EOF there).
//   - A request with no declared Content-Length (chunked transfer
//     encoding) is buffered and capped by the pipeline (Accept.MaxBodySize)
//     and Engine.Evaluate hands that buffered body to Coraza, so these
//     rules see chunked bodies the same way as declared-length ones.
//   - There is no per-part header count in SecLang, so 212001 caps the
//     total across all parts. A legitimate part has at most the three
//     headers RFC 7578 defines.
//
// Design notes:
//
//   - IDs 212001-212003, in the 212000 range reserved for Barbacana custom
//     multipart-shape rules. See the custom-ID registry next to the
//     injection point in NewEngine (crs.go).
//   - 212001: more than 4000 part header lines across all parts. A form at
//     PHP's default input ceiling (max_input_vars=1000 plus
//     max_file_uploads=20 parts), with every part carrying all three RFC
//     7578 headers, comes to 3060. 4000 leaves headroom above that. It is
//     still orders of magnitude below the header counts an out-of-memory
//     condition needs.
//   - 212002: the multipart processor failed with "message too large".
//     Only an oversized part header block produces that error.
//   - 212003: more than 20 empty file controls (Content-Disposition with a
//     filename parameter whose value is empty). 20 is PHP's default
//     max_file_uploads, the limit the advisory says these parts slip past.
//     The count lives in tx.barbacana_empty_file_controls.
//   - All three are severity:CRITICAL and add the critical score to the
//     inbound PL1 anomaly score, so one match meets the blocking
//     threshold.
//
// Mapped to the catalog leaves `php-php2shell-part-headers`
// (212001, 212002) and `php-php2shell-empty-file-controls`
// (212003). Disabling a leaf emits SecRuleRemoveById for its IDs via the
// standard mechanism.
const barbacanaPHP2ShellMultipartRules = `
SecRule &MULTIPART_PART_HEADERS "@gt 4000" \
    "id:212001,\
    phase:2,\
    block,\
    t:none,\
    msg:'PHP2Shell (CVE-2026-109618 / GHSA-w8hw-w9fx-j79w) request vector: multipart part-header flood (vector match, not proof of exploitation)',\
    logdata:'%{MATCHED_VAR} multipart part header lines (limit 4000)',\
    tag:'application-multi',\
    tag:'language-php',\
    tag:'platform-multi',\
    tag:'attack-dos',\
    tag:'attack-rce',\
    tag:'barbacana-custom',\
    severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

SecRule REQBODY_PROCESSOR "@streq MULTIPART" \
    "id:212002,\
    phase:2,\
    block,\
    t:none,\
    msg:'PHP2Shell (CVE-2026-109618 / GHSA-w8hw-w9fx-j79w) request vector: multipart part header block exceeds parser limit (vector match, not proof of exploitation)',\
    logdata:'%{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-php',\
    tag:'platform-multi',\
    tag:'attack-dos',\
    tag:'attack-rce',\
    tag:'barbacana-custom',\
    severity:'CRITICAL',\
    chain"
    SecRule REQBODY_PROCESSOR_ERROR_MSG "@contains message too large" \
        "t:none,\
        setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

SecRule REQBODY_PROCESSOR "@streq MULTIPART" \
    "id:212003,\
    phase:2,\
    block,\
    t:none,\
    msg:'PHP2Shell (CVE-2026-109618 / GHSA-w8hw-w9fx-j79w) request vector: too many empty file controls (vector match, not proof of exploitation)',\
    logdata:'%{TX.barbacana_empty_file_controls} empty file controls (limit 20)',\
    tag:'application-multi',\
    tag:'language-php',\
    tag:'platform-multi',\
    tag:'attack-dos',\
    tag:'attack-rce',\
    tag:'barbacana-custom',\
    severity:'CRITICAL',\
    chain"
    SecRule MULTIPART_PART_HEADERS "@rx (?i)^content-disposition\s*:.*;\s*filename\s*=\s*(?:\x22\x22\s*)?(?:;|$)" \
        "t:none,\
        setvar:'tx.barbacana_empty_file_controls=+1',\
        chain"
        SecRule TX:barbacana_empty_file_controls "@gt 20" \
            "t:none,\
            setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
`
