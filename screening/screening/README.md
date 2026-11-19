# @dekimuhq/screening

Anchored Screening Receipts (AScR, `ar.screening.v1`): verify (default export) and issue (`./issue`).

A receipt proves **which list file was checked, when, by which matcher, and with what result**. It never proves sanctions status, and the result words are `none_at_threshold | candidate`, never "clear". The screened name is a salted commitment; `mintScreeningV1` returns the reveal (salt + name) for the caller to keep, export to the owner and erase on erasure.

Spec: https://github.com/dekimuhq/anchors-spec/tree/main/screening
