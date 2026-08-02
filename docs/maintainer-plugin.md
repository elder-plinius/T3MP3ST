# Shared BT6 Maintainer Plugin

T3MP3ST consumes `bt6-maintainer` from the shared
[`jmagly/bt6-aiwg-plugins`](https://github.com/jmagly/bt6-aiwg-plugins)
repository. The public mirror is
[`roctinam/bt6-aiwg-plugins`](https://git.integrolabs.net/roctinam/bt6-aiwg-plugins).

The repository profile is `.aiwg/bt6-maintainer.yaml`. The release source,
version, commit, and wrapper tree are pinned in
`.aiwg/bt6-maintainer.lock.json`.

## Verify the pinned release

```bash
npm run maintainer:check
aiwg doctor --project-local
```

The check refreshes AIWG's Git package cache, verifies the pinned commit and Git
tree, and compares the project wrapper byte-for-byte with the shared release.

## Synchronize and deploy

After intentionally updating the lock file to a reviewed shared release:

```bash
npm run maintainer:sync
```

The sync command uses `aiwg install` to fetch the external repository, verifies
the immutable commit/tree, stages the wrapper, deploys it through `aiwg use` to
Claude and Codex, rebuilds discovery, and runs the project-local doctor. The
previous project-local wrapper is restored if deployment fails; rerun the sync
to reconcile provider deployment artifacts after correcting the reported
failure.

AIWG issue [#1997](https://git.integrolabs.net/roctinam/aiwg/issues/1997)
tracks direct discovery of nested standalone wrappers by `aiwg install`. Until
that is resolved, the sync command bridges the cached repository to the
project-local wrapper path. AIWG issues
[#1996](https://git.integrolabs.net/roctinam/aiwg/issues/1996) and
[#1998](https://git.integrolabs.net/roctinam/aiwg/issues/1998) track the legacy
local-source installer crash and unsafe removal classification respectively.

Do not restore `.aiwg/addons/t3mp3st-maintainer`; reusable maintainer behavior
belongs in the shared repository, while T3MP3ST-specific commands and risk paths
belong in the repository profile.
