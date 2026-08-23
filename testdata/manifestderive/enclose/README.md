# Hand-checked enclose golden cases

`cases.json` lists **25** real upstream fix commits. For each, the changed
C/C++ blobs and line numbers were extracted from a local `git show`; enclosing
function names were produced by tree-sitter (not hunk-trailer regex).

`hand_checked: true` means a human opened the upstream commit, confirmed the
`expected_symbols` appear in the patch’s affected function definitions, and
confirmed those symbols are present in the deriver output.

Do not mark new cases `hand_checked` without reading the commit.
