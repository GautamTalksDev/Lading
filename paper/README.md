# Paper source

`body.tex` holds the full text and is shared by both wrappers.

`lading-paper-acmart.tex` is the submission wrapper, ACM sigconf. Compile
this one. It requires `acmart.cls`, which is available on Overleaf and in
full TeX Live installations but is not present in every distribution.

`preview.tex` is a two column `article` wrapper used only to produce a
readable PDF where `acmart` is unavailable. It is not the submission
format. Do not submit or cite a PDF built from it. Build artifacts are
gitignored for that reason.

Both wrappers open with a pre submission checklist in comments. Work
through every item before posting anywhere.

Figures in this paper are amended against FINDING-003. Where a number
differs from an earlier draft, RESULTS.md and the files under `audit/`
carry the correction record.
