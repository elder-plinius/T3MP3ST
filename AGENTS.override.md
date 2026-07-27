# Operator Additions

## Contributor Courtesy Merge Cleanup

When a contributor has substantially completed significant changes requested in review and only low-impact merge work remains, maintainers may finish that cleanup and merge the pull request as a courtesy.

This permission is limited to mechanical, low-risk work such as resolving a small conflict with an already-merged change, preserving an established default, or adding narrowly scoped regression coverage for the reviewed behavior. Re-run the applicable review, test, and exact-head merge gates before merging, and tell the contributor what was changed.

If the merge or rebase has a large surface area, changes behavior beyond the reviewed intent, requires product or architectural judgment, or exposes additional substantive defects, do not take over the branch. Ask the contributor to rebase and correct the issues, then re-review their updated head.
