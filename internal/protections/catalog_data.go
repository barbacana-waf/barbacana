package protections

// catalogValue returns the full Catalog. Sourced from
// .planning/protection_taxonomy_proposal.md verbatim. Editing any leaf
// in this file is editing the catalog directly — there is no
// regeneration step. TestCatalogIntegrity verifies structural invariants
// after every change.
func catalogValue() []Group {
	return []Group{
		groupSQL(),
		groupPHP(),
		groupJava(),
		groupRuby(),
		groupPerl(),
		groupIIS(),
		groupJavaScript(),
		groupCrossSiteScripting(),
		groupCommandInjection(),
		groupLocalFileAccess(),
		groupRemoteFileFetch(),
		groupOutboundRequestForgery(),
		groupFileUpload(),
		groupHTTPCompliance(),
		groupHTTPAttacks(),
		groupLDAPInjection(),
		groupMailProtocolInjection(),
		groupTemplateInjection(),
		groupDataURIAbuse(),
		groupServerDataLeakage(),
		groupWebShellDetection(),
		groupScannerDetection(),
		groupSessionFixation(),
		groupHTTP2(),
		groupRequestValidation(),
		groupJSONParsing(),
		groupXMLParsing(),
		groupResourceLimits(),
		groupOpenAPI(),
		groupResponseHeaders(),
		groupResponseInspection(),
	}
}
