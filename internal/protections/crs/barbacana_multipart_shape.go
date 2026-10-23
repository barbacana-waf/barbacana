package crs

// barbacanaMultipartShapeRules are Barbacana-owned Coraza SecRules that cap
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
//   - Coraza only sees the first max_inspect_size bytes of the body
//     (route inspection.max_inspect_size, default 128KB, passed as
//     SecRequestBodyLimit). Barbacana never sets SecRequestBodyLimitAction,
//     so Coraza's default applies: Reject in blocking mode, which turns
//     away any declared-length body at or above that size before these
//     rules run. So in blocking mode they always see the whole body of any
//     request that gets through. In detect_only mode Coraza forces
//     ProcessPartial: rules see only the first window, and a part whose
//     header block is cut off by the window is not counted (Go reports a
//     malformed header or a clean EOF there).
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
const barbacanaMultipartShapeRules = `
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
