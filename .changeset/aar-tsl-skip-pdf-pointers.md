---
"@dekimuhq/aar-tsl": patch
---

Skip PDF pointers in the LOTL (only machine-readable TSLs are parsed) and isolate per-country parse failures, so one national list can no longer fail the whole snapshot. Before this, `buildTslSnapshot()` threw on the human-readable PDF pointers the LOTL lists beside the XML ones for 11 countries.
