# @dekimuhq/screening

Anchored Screening Receipts (AScR, `ar.screening.v1`): verify (default export) and issue (`./issue`).

A receipt proves **which list file was checked, when, by which matcher, and with what result**. It never proves sanctions status, and the result words are `none_at_threshold | candidate`, never "clear". The screened name is a salted commitment; `commitScreenedName(name)` draws a fresh per-screen salt and returns `{ subject_commit, reveal }`; pass `subject_commit` to `mintScreeningV1` and keep the reveal, export it to the owner and erase it on erasure.

Spec: https://github.com/dekimuhq/anchors-spec/tree/main/screening
