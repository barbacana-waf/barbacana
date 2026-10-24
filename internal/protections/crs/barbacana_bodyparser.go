package crs

// Request body parser selection.
//
// Coraza picks a body parser per request from tx.REQBODY_PROCESSOR. CRS does
// not pick one for ordinary types: it only sets JSON for the +json suffix and
// the AWS JSON types (rules 901360 and 901370), and leaves the rest to the
// engine's recommended configuration (coraza.conf-recommended rules 200000 and
// 200001), which Barbacana does not load. With nothing set, Coraza parses every
// body that is not multipart as URL-encoded. An XML document then becomes form
// fields cut at each "=", so a body that begins <?xml version="1.0" turns into
// a field named "<?xml version" that XSS rule 941100 blocks, and every XML API
// (WebDAV, CalDAV, SOAP) fails for that reason. A JSON body is scanned as one
// raw field name, which CRS rules were not written against.
//
// barbacanaBodyProcessorRules select the parser from Content-Type, in the same
// way coraza.conf-recommended does, so CRS sees the variables its rules target:
// XML:/* and XML://@* for XML, and one ARGS entry per key for JSON.
//
// The catch with a structured parser is the body that does not parse. Under
// the URL-encoded fallback its raw text was scanned anyway; under the XML or
// JSON parser a body that fails to parse yields no variables at all, so
// malformed content under a JSON or XML Content-Type would pass every body rule
// unseen, and any lenient parser behind the WAF would still read it.
// Barbacana's native JSON/XML guards leave malformed bodies to CRS on purpose
// ("not valid JSON — let CRS handle it"). Rule 213003 closes the gap: a body
// that fails its declared parser scores as a critical match, unless the body was
// cut short at the inspection window (INBOUND_DATA_ERROR), where the parse
// failure is only the cut.
//
// There is a second thing the old behaviour did by accident. Read as form
// data, every XML body that opened with a DOCTYPE was cut into fields full of
// characters the XSS and path rules react to, so XXE payloads were blocked
// without any rule being about XXE. Parsed as XML, a DOCTYPE and the entity
// declarations in it are not part of any variable the CRS rules read (Go's XML
// tokenizer reports them as directives, not text), and CRS has no XXE rule.
// The native XML guard (internal/protections/request) is that rule: an
// external DOCTYPE or an entity declared with SYSTEM or PUBLIC, the two ways a
// request makes the server read a file or fetch a URL while parsing. It is
// native rather than a rule here because under the XML parser no variable holds
// the raw body (REQUEST_BODY is only set by the URL-encoded and RAW parsers).
//
// Rule IDs: 213001–213002 only pick a parser and match on every request of
// those types, so they are orchestration rules (no catalog leaf, like the 9000xx
// setup rules); 213003 is the detection, mapped to the catalog leaf
// `http-compliance-malformed-body`.
const barbacanaBodyProcessorRules = `
SecRule REQUEST_HEADERS:Content-Type "@rx ^(?:application/(?:soap\+|[a-z0-9.!#$&_^+-]*\+)?|text/)xml(?:\s*;.*)?$" \
    "id:213001,\
    phase:1,\
    pass,\
    nolog,\
    t:none,t:lowercase,\
    ctl:requestBodyProcessor=XML"

SecRule REQUEST_HEADERS:Content-Type "@rx ^application/json(?:\s*;.*)?$" \
    "id:213002,\
    phase:1,\
    pass,\
    nolog,\
    t:none,t:lowercase,\
    ctl:requestBodyProcessor=JSON"
`

const barbacanaBodyParseRules = `
SecRule REQBODY_PROCESSOR "@rx ^(?:JSON|XML)$" \
    "id:213003,\
    phase:2,\
    block,\
    t:none,\
    msg:'Request body is not valid for its declared Content-Type (JSON or XML)',\
    logdata:'%{REQBODY_PROCESSOR} body failed to parse: %{REQBODY_PROCESSOR_ERROR_MSG}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-protocol',\
    tag:'barbacana-custom',\
    severity:'CRITICAL',\
    chain"
    SecRule REQBODY_ERROR "!@eq 0" \
        "t:none,\
        chain"
        SecRule INBOUND_DATA_ERROR "@eq 0" \
            "t:none,\
            setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
`
