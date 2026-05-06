package crs

// barbacanaXSSRules are Barbacana-owned Coraza SecRule directives that
// fill XSS coverage gaps no upstream CRS rule addresses at any
// paranoia level. Each rule:
//
//   - uses an ID in the 210000 range, outside the CRS 9XX,XXX block
//   - is severity:CRITICAL and contributes to the inbound PL1
//     anomaly score so it composes with the rest of the engine
//   - tags itself attack-xss and barbacana-custom for grep-ability
//     in audit logs
//   - scans the same surface as the CRS PL1 sibling 941100 (cookies,
//     User-Agent, ARGS, REQUEST_FILENAME, XML), which means it
//     automatically picks up the synthetic ARGS produced by the
//     base64-decoding stage
//
// These rules are mapped to the catalog leaf
// `cross-site-scripting-function-call-evasion`. Disabling the leaf
// emits SecRuleRemoveById for each ID via the standard mechanism.
//
// The regexes were validated against the v0.5 base64-decoding
// gotestwaf bypass set and an augmented clean-text corpus — see
// xss_native_probe_test.go for the methodology and the
// per-payload coverage matrix.
const barbacanaXSSRules = `
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|ARGS_NAMES|ARGS|REQUEST_FILENAME|XML:/* "@rx (?i)\b(?:alert|confirm|prompt|eval|setTimeout|setInterval|Function)\s*\.\s*(?:call|apply|bind)\s*\(" \
    "id:210001,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,\
    msg:'XSS via Function.prototype.{call|apply|bind} on dangerous global',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-xss',\
    tag:'barbacana-custom',\
    severity:'CRITICAL',\
    setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|ARGS_NAMES|ARGS|REQUEST_FILENAME|XML:/* "@rx (?i)\(\s*(?:alert|confirm|prompt|eval)\s*\)\s*\(" \
    "id:210002,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,\
    msg:'XSS via grouping-paren evasion on dangerous global',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-xss',\
    tag:'barbacana-custom',\
    severity:'CRITICAL',\
    setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|ARGS_NAMES|ARGS|REQUEST_FILENAME|XML:/* "@rx (?i)\b(?:alert|confirm|prompt|eval|setTimeout|setInterval)\s*\?\s*\.\s*\(" \
    "id:210003,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,\
    msg:'XSS via optional-chaining call on dangerous global',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-xss',\
    tag:'barbacana-custom',\
    severity:'CRITICAL',\
    setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
`
