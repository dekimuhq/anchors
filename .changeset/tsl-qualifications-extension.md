---
"@dekimuhq/aar-tsl": minor
---

Snapshot entries now carry what a CA/QC service is listed FOR and since when. `parseTsl` reads the `AdditionalServiceInformation` URIs (`ForeSignatures`, `ForeSeals`, `ForWebSiteAuthentication`) and the `Qualifications` qualifier URIs of each service, and keeps each `ServiceHistoryInstance` with its own status, start time and extensions. New `TslServiceEntry` fields: `additional_service_info`, `qualifiers`, `status_history` (always present, empty when the list has none).

Why: a relying party that only has "granted CA/QC" cannot tell a website-certificate CA from a signature CA, and cannot ask whether a service was listed, and for what, at the time something was signed. Entry hashes change, so a snapshot built with this version has a different Merkle root from one built before it; a consumer should treat a snapshot whose entries lack the new fields as predating them.
