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
