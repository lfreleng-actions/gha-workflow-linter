<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# 🔍 GHA Workflow Linter

[![GitHub Actions](https://github.com/modeseven-lfit/gha-workflow-linter/actions/workflows/build-test.yaml/badge.svg)](https://github.com/modeseven-lfit/gha-workflow-linter/actions/workflows/build-test.yaml)
[![PyPI version](https://img.shields.io/pypi/v/gha-workflow-linter.svg)](https://pypi.org/project/gha-workflow-linter/)
[![Python Support](https://img.shields.io/pypi/pyversions/gha-workflow-linter.svg)](https://devguide.python.org/versions/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A comprehensive GitHub Actions workflow linter that validates action and
workflow calls against remote repositories. GHA Workflow Linter ensures your GitHub
Actions workflows reference valid repositories, branches, tags, and commit SHAs.

## Features

<!-- markdownlint-disable MD013 -->

- **🔧 Auto-Fix**: Automatically fix invalid references and pin actions to commit SHAs
- **🧪 Testing Skip**: Auto-fixing skips actions with 'test' in comments by default (use `--fix-test-calls` to enable)
- **🔒 SHA Pinning Enforcement**: Requires actions using commit SHAs for security (configurable)
- **🔑 Automatic Authentication**: Auto-detects GitHub tokens from GitHub CLI when available
- **📦 Local Caching**: Stores validation results locally to improve performance and reduce API calls
- **Multi-format Support**: Works as CLI tool, pre-commit hook, and GitHub Action
- **Comprehensive Validation**: Validates repositories, references, and syntax
- **Parallel Processing**: Multi-threaded validation for faster execution
- **Flexible Configuration**: YAML/JSON config files with environment overrides
- **Rich Output**: Clear error reporting with file paths and line numbers
- **SSH Support**: Respects SSH configuration and agent for private repositories
- **Rate Limiting**: Built-in throttling to respect API limits

<!-- markdownlint-enable MD013 -->

## Installation

### From PyPI

```bash
uv add gha-workflow-linter
```

### From Source

```bash
git clone https://github.com/modeseven-lfit/gha-workflow-linter.git
cd gha-workflow-linter
uv pip install -e .
```

### Development Installation

```bash
git clone https://github.com/modeseven-lfit/gha-workflow-linter.git
cd gha-workflow-linter
uv sync --extra dev
```

## Authentication

GHA Workflow Linter uses the GitHub GraphQL API for efficient validation. Authentication
is **optional** but **highly recommended** to avoid rate limiting.

### Automatic Authentication (Recommended)

If you have [GitHub CLI](https://cli.github.com/) installed and authenticated,
the linter will **automatically** get a token when needed:

```bash
# No token setup required if GitHub CLI has authentication!
gha-workflow-linter lint
```

When no token exists, you'll see:

```text
⚠️ No GitHub token found; attempting to get using GitHub CLI
✅ GitHub token retrieved from GitHub CLI
```

### Manual Token Setup

If you don't use GitHub CLI or prefer manual setup:

1. **Create a Personal Access Token:**

   <!-- markdownlint-disable MD013 -->

   - Go to [GitHub Settings > Developer settings > Personal access tokens](https://github.com/settings/tokens)
   - Click "Generate new token (classic)"
   - Select scopes: `public_repo` (for public repositories) or `repo` (for
     private repositories)
   - Copy the generated token

   <!-- markdownlint-enable MD013 -->

2. **Set the token via environment variable:**

   ```bash
   export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
   gha-workflow-linter lint
   ```

3. **Or pass the token via CLI flag:**

   ```bash
   gha-workflow-linter lint --github-token ghp_xxxxxxxxxxxxxxxxxxxx
   ```

### Authentication Priority

The linter uses the following priority order:

1. **CLI flag** (`--github-token`)
2. **Environment variable** (`GITHUB_TOKEN`)
3. **GitHub CLI fallback** (`gh auth token`)

### Rate Limits

<!-- markdownlint-disable MD013 -->

<!-- markdownlint-disable MD060 -->

| Authentication    | Requests/Hour | Recommended Use                          |
| ----------------- | ------------- | ---------------------------------------- |
| **With Token**    | 5,000         | ✅ Production, CI/CD, large repositories |
| **Without Token** | 60            | ⚠️ Small repositories, testing purposes  |

<!-- markdownlint-enable MD060 -->

<!-- markdownlint-enable MD013 -->

**Without any authentication, you'll see:**
`⚠️ No GitHub token available; API requests may be rate-limited`

## Usage

### Command Line Interface

```bash
# Show help with version
gha-workflow-linter --help

# Scan current directory (automatic authentication via GitHub CLI)
gha-workflow-linter lint

# Scan with environment token
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
gha-workflow-linter lint

# Scan specific path with CLI token
gha-workflow-linter lint /path/to/project --github-token ghp_xxxxxxxxxxxxxxxxxxxx

# Use custom configuration
gha-workflow-linter lint --config config.yaml

# JSON output format
gha-workflow-linter lint --format json

# Verbose output with 8 parallel workers
gha-workflow-linter lint --verbose --workers 8

# Exclude patterns
gha-workflow-linter lint --exclude "**/test/**" --exclude "**/docs/**"

# Disable SHA pinning policy (allow tags/branches)
gha-workflow-linter lint --no-require-pinned-sha

# Repair invalid references and pin to SHAs
gha-workflow-linter lint --action-calls fix

# Repair including actions with 'test' in comments (default skips them)
gha-workflow-linter lint --action-calls fix --fix-test-calls

# Report without touching the working tree
gha-workflow-linter lint --action-calls report

# Run without any authentication (limited to 60 requests/hour)
# This happens when GitHub CLI is not installed/authenticated AND no token exists
# Shows: ⚠️ No GitHub token available; API requests may be rate-limited
gha-workflow-linter lint
```

### Check Modes

The linter runs independent checks. Each takes one option saying what it
should do:

<!-- markdownlint-disable MD013 -->

<!-- markdownlint-disable MD013 MD060 -->

| Option           | Modes                      | Default  | Check                                    |
| ---------------- | -------------------------- | -------- | ---------------------------------------- |
| `--action-calls` | `off｜report｜fix｜update` | `fix`    | Action and workflow `uses:` references   |
| `--allow-list`   | `off｜report｜update`      | `report` | `harden-runner` allow-list pins          |
| `--stderr-merge` | `off｜report`              | `report` | Stderr merged into output used as data   |
| `--python-path`  | `off｜report`              | `report` | Python runs that take in workspace files |

<!-- markdownlint-enable MD013 MD060 -->

<!-- markdownlint-enable MD013 -->

The modes form a ladder of escalating intervention:

- **`off`** — the check does not run. It validates nothing, reports
  nothing, writes nothing, and takes no part in the exit code. Every
  check shares one workflow discovery pass rather than owning its own,
  so the scan itself still happens: it reports an unreadable path, and
  the allow-list check reads it.
- **`report`** — the check runs and reports. It never writes.
- **`fix`** — as `report`, and repairs what is wrong *without changing
  which version a reference names*. Pinning `@v4` to the commit SHA of
  v4 counts as a repair, as does peeling an annotated tag to its commit.
  A reference that no longer resolves forms the exception, because it
  cannot stay.
- **`update`** — as `fix`, and also advances references to newer
  releases.

```bash
# Report; never touch the working tree
gha-workflow-linter lint --action-calls report

# Run nothing but the allow-list check
gha-workflow-linter lint --action-calls off

# Repair and advance to the latest releases
gha-workflow-linter lint --action-calls update
```

The linter refuses a mode a check does not offer, rather than
downgrading it:

```console
$ gha-workflow-linter lint --allow-list fix
Configuration error: --allow-list does not support mode 'fix': repairing
an allow-list pin without advancing its version is not implemented yet
[...]; use 'update'. Supported modes: off, report, update
```

#### Modes do not decide what fails the run

The `--verify-*` flags carry a separate axis: whether a finding fails
the run.

```bash
# Repair what the linter can, and fail if anything remains outdated
gha-workflow-linter lint --action-calls fix --verify-action-calls

# Audit pins without touching the working tree
gha-workflow-linter lint --action-calls report --verify-action-calls
```

The two axes stay orthogonal on purpose. `--action-calls fix` answers
*change my files*; `--verify-action-calls` answers *fail my build*.
Neither implies the other, and you want both together. Every mode that
runs the check detects outdated calls, so `--verify-action-calls` fails
on them in `report` as in `fix` and `update`; `report` reads release
information from GitHub to do so, as the other modes do. Defect
findings — a reference that is wrong now — always count towards the
exit code in **every mode that runs the check**. `off` sits outside
that statement rather than contradicting it: a check that detects
nothing has nothing to count.

#### Superseded flags

The older flags keep working and name their replacement once:

<!-- markdownlint-disable MD013 -->

| Deprecated            | Use instead             |
| --------------------- | ----------------------- |
| `--auto-fix`          | `--action-calls fix`    |
| `--no-auto-fix`       | `--action-calls report` |
| `--update-actions`    | `--action-calls update` |
| `--no-update-actions` | `--action-calls fix`    |
| `--auto-latest`       | `--action-calls update` |
| `--no-auto-latest`    | `--action-calls fix`    |
| `--no-allow-list`     | `--allow-list off`      |
| `--update-allow-list` | `--allow-list update`   |
| `--verify-actions`    | `--verify-action-calls` |

<!-- markdownlint-enable MD013 -->

When a mode option appears beside one of these, the mode wins, and the
run reports the flag it ignored.

One spelling does change. `--allow-list` was a boolean pair, so the bare
form meant "enable"; it now requires a mode, because an option cannot
both take a value and be usable without one. Write `--allow-list report`
for the old meaning. `--no-allow-list` keeps working as before.

### Auto-Fix Feature

The linter can automatically fix invalid action references and pin them to
commit SHAs:

```bash
# Repair broken references, keeping the version each one names (default)
gha-workflow-linter lint --action-calls fix

# Report findings; never write
gha-workflow-linter lint --action-calls report

# Repair and advance to the latest release
gha-workflow-linter lint --action-calls update
```

**Updates do not move a pin backwards.** A resolved "latest" release
names the newest at the moment of discovery, and a cached one can be
older still — so a pin something else has advanced in the meantime
(Dependabot, Renovate, a colleague, an earlier run) can be newer than the
target. The linter leaves such a call alone rather than rewriting it
backwards and reporting the downgrade as a successful update. The same
applies when repairing a broken pin: a reference that no longer resolves
is not replaced by a release older than the one its comment claims.

Establishing that needs a version to compare, which comes from the
reference when that is a version tag, and otherwise from the version
comment. A commit pin carrying neither states no version, so it takes
the ordinary update path. An action that has moved to a new repository
is likewise exempt, since two projects' version numbers are not
comparable.

**Skip Testing Actions**: By default, auto-fix skips actions with 'test' in
their comments (case-insensitive). This is useful when you have experimental or
testing branches that you don't want to update yet. Use `--fix-test-calls` to
enable auto-fixing for these actions:

```yaml
# The tool skips these by default (unless you use --fix-test-calls)
- uses: actions/checkout@master  # Testing
- uses: myorg/my-action@test-branch  # testing new feature
- uses: myorg/my-action@experimental  # Test version
```

Example output (default behavior, test actions skipped):

```text
⏩ Skipped 3 testing action(s) in 1 file(s):

📄 .github/workflows/build.yaml
  ⏩ uses: actions/checkout@master  # Testing
  ⏩ uses: myorg/my-action@test-branch  # testing new feature
  ⏩ uses: myorg/my-action@experimental  # Test version

🔧 Auto-fixed issues in 1 file(s):

📄 .github/workflows/build.yaml
  - - uses: actions/cache@v3
  + - uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830 # v4.3.0
```

### Exit Codes

<!-- markdownlint-disable MD013 -->

| Code | Meaning                                                               |
| ---- | --------------------------------------------------------------------- |
| `0`  | No failing findings                                                   |
| `1`  | Defects found, or a fixer modified files, or the run itself failed    |
| `2`  | Command-line usage error (reserved by the argument parser)            |
| `3`  | `--verify-allow-list` and stale allow-list pins remain                |
| `4`  | `--verify-allow-list` and the tool could not reach the latest release |
| `5`  | `--verify-action-calls` and outdated action calls remain              |
| `6`  | Rate-limited API, and the run asked it to verify or update            |
| `7`  | `--verify-python-path` and a python-path finding that gates remains   |
| `8`  | `--verify-stderr-merge` and a stderr merge used as data remains       |

<!-- markdownlint-enable MD013 -->

When more than one applies, the most significant wins: `6`, then `4`,
then `3`, then `5`, then `7`, then `8`, then `1`. A check that could
not run outranks a stale result, because enforcement reporting success
when it never looked is worse than useless. A condition you asked about
by name outranks the generic `1`, and nothing masks it.

Codes `3`, `4`, `5`, `7` and `8` require the matching `--verify-*` flag.
Without it, the linter reports those findings and leaves the exit code
alone.

#### Rate limiting

A rate-limited run makes no further API request: validation, the fixer
and the allow-list check are all skipped, as they were when the tool
ended the process on discovering a throttle. The pre-flight query that
found the throttle is the last request it makes. The run has nothing to
report and no grounds for reporting a pass. What it does about that
depends on whether you asked it for anything:

- **Advisory runs exit `0`**, as they always have. A throttle at GitHub
  must not break every build that merely wanted advice.
- **A run that asked exits `6`.** "Could not look" answers neither *is
  this current?* nor *make this current*, so `--verify-action-calls`,
  `--verify-allow-list`, `--action-calls update` and `--allow-list
  update` all
  produce `6`, as do the configuration-file settings behind them. This is
  the same distinction `4` draws for an unresolved allow-list check.

Turning off a stage removes the demand with it, so
`--allow-list off --verify-allow-list` exits `0` throttled or not: the
check that would have answered it never runs either way. The same holds
for the action-call settings under `--action-calls report`.

Either way the run still scans, so a path it cannot read is still
reported; it still emits its `--format json` document; and that document
carries `"rate_limited": true`, so a scheduled sweep can tell a clean
estate from one it never managed to examine. Text output says so too,
in place of the usual "All action calls are valid", and a sweep summary
labels the repository `rate-limited` rather than `findings`.

GitHub counts the GraphQL and REST budgets separately, and the linter
uses both: validation goes through GraphQL, while the fixer and the
reference resolver call REST. Pre-flight checks both, since exhausting
either one leaves work the run cannot do.

It checks both regardless of the modes in force, which is coarser than
it could be. `--action-calls report` enables no REST-backed work, yet
an exhausted REST budget still counts as a throttle and skips the
GraphQL validation that would have succeeded. Narrowing pre-flight to
the budgets a run actually needs belongs with the detection and
remediation split, which is what makes "this mode needs REST"
answerable.

### Verifying Action Currency

`--verify-action-calls` treats outdated action calls as errors,
mirroring `--verify-allow-list`:

```bash
# Report outdated actions but do not fail (the default)
gha-workflow-linter lint

# Fail when any action call has a newer release available
gha-workflow-linter lint --verify-action-calls
```

This is useful in a scheduled compliance run, where you want to know
that something has fallen behind, without blocking a developer's commit
over it.

### Update Cooldown

To guard against supply-chain attacks and retracted releases, the linter
can refuse to update an action call to a release until that release has
been public for a set number of days. This mirrors the
[Dependabot `cooldown`](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference#cooldown-)
policy.

```bash
# Update to releases at least 7 days old
gha-workflow-linter lint --action-calls update --cooldown 7

# Disable the cooldown (the default behaviour)
gha-workflow-linter lint --action-calls update --cooldown 0
```

When `--cooldown` is not supplied, the linter walks up from the scanned
path to find a `.github/dependabot.yml` (or `.yaml`) file and reuses its
`cooldown.default-days` value, preferring the `github-actions` ecosystem.
The linter reports that value once:

```text
Using cooldown timer/value [7] from dependabot configuration 🤖
```

When the linter finds no Dependabot configuration (and no flag sets a
value) the cooldown defaults to `0`, preserving the original behaviour.
The linter picks the newest release that satisfies the cooldown window,
so it still updates an action to an older-but-eligible release when the
latest release remains inside the window.

This cooldown governs action calls alone. Allow-list pins have their own
cooldown, `--allow-list-cooldown`, which defaults to `0` and never reads
the Dependabot configuration; see
[Allow-List Pin Checking](#allow-list-pin-checking).

> Note: the cooldown relies on a verifiable publication timestamp for
> each candidate: the release publish date (GitHub API GraphQL/REST) or
> an annotated tag's tagger date. Lightweight tags carry no creation
> timestamp of their own, and the Git validation method cannot expose
> release dates, so the linter skips candidates it cannot date while a
> cooldown applies.

### Allow-List Pin Checking

The `lfreleng-actions` organisation pins its
[`step-security/harden-runner`](https://github.com/step-security/harden-runner)
egress allow-list using a custom `uses:`-style coordinate consumed by
[`harden-runner-block-action`][hrba]:

[hrba]: https://github.com/lfreleng-actions/harden-runner-block-action

<!-- markdownlint-disable MD013 -->

```yaml
# Internal workflow, shorthand form
- uses: lfreleng-actions/harden-runner-block-action@6db537b3...  # v0.2.1
  with:
    config: '@18d9c4446bea555d0783e850f6d295f844fe8f67'  # v0.1.1

# Reusable-workflow input default, explicit path form
harden_runner_allowlist:
  type: string
  default: 'lfreleng-actions//.github/harden-runner/lfreleng-actions/allow_list.txt@bf6642f6...'  # v0.12.2

# Workflow or job env: variable, read by expression
env:
  HARDEN_RUNNER_ALLOWLIST: 'lfreleng-actions//.github/harden-runner/lfreleng-actions/allow_list.txt@8f4f0cf8...'  # v0.5.1
```

<!-- markdownlint-enable MD013 -->

The linter finds `env:` pins at the workflow level and under
`jobs.<job>.env` when the variable's value names `allow_list.txt` or its
name matches `*allow_list*`, `*allowlist*` or `*allow-list*`. The
`config: ${{ env.HARDEN_RUNNER_ALLOWLIST }}` that consumes such a
variable is an expression, not a pin, and the linter skips it.

These are values of `config:`, `default:` and `env:` keys, **not** `uses:`
references, so Dependabot cannot see or bump them. They drift without
warning, and a stale pin means a block-mode job lacks newly allow-listed
endpoints, producing confusing `ECONNREFUSED` failures long after
someone corrected the allow-list itself.

The linter detects these pins, resolves the host repository's latest
release (dereferencing the annotated tag to its commit), and reports
pins that lag behind.

```bash
# Detect stale pins; reports them but never fails (the default)
gha-workflow-linter lint

# Fail the run when stale pins remain
gha-workflow-linter lint --verify-allow-list

# Skip the check entirely
gha-workflow-linter lint --allow-list off

# Show pins silenced by a suppression directive
gha-workflow-linter lint --show-suppressed

# Rewrite stale pins in place
gha-workflow-linter lint --allow-list update
```

`--allow-list update` changes the reference and its version comment and
nothing else. Quoting style, the spacing before `#`, the comment's
position (inside or outside the quotes) and any suppression directive
all survive the edit, so the resulting diff stays reviewable. Writes are
atomic and preserve the file's existing line endings. As with the action
fixer, a run that modifies files exits `1` so a pre-commit hook or CI job
notices that the tree changed.

This check follows an `lfreleng-actions` convention rather than
GitHub-native validation, so it stays **advisory by default**: the
linter reports findings as warnings and leaves the exit code alone.
Enforcement is opt-in via `--verify-allow-list`. When the linter cannot
resolve the latest release (no token, no network, rate limited), the
default mode prints a notice and carries on; under
`--verify-allow-list` it exits `4` instead of passing.

A pin counts as stale when the target is newer, and not otherwise.
It leaves a repository already ahead of the cooldown-eligible release
alone, so a cooldown never recommends a downgrade.

Some references float on purpose. `harden-runner-block-action` accepts
an unpinned same-organisation supplemental list when a paired flag in
the same mapping opts in, and the linter honours that flag:

<!-- markdownlint-disable MD013 -->

| Reference key                          | Paired flag                           |
| -------------------------------------- | ------------------------------------- |
| `harden_runner_supplemental_allowlist` | `harden_runner_supplemental_unpinned` |
| `supplemental_config`                  | `supplemental_unpinned`               |

<!-- markdownlint-enable MD013 -->

The flag sits beside the reference in a reusable-workflow call's
`with:` block, or, for a `workflow_call` input, as the paired input's
`default`. A literal `true` (unquoted, or the string `true` in any
case) means a floating reference produces no finding, and
`--allow-list update` leaves it alone. A flag written as an expression
(`${{ … }}`) leaves the decision to the caller at run time, so the
linter still reports the reference as unpinned but never rewrites it.
A `false` or absent flag changes nothing. A reference shared through a
YAML alias takes every use's flag into account: when the uses disagree,
the linter reports the floating reference but never rewrites it, since
the one value would pin a use that opts in. A reference under these
keys that does name a commit SHA still counts as stale when it lags.

#### Allow-list cooldown

The target is the host repository's newest release from the moment its
tag exists. Allow-list pins take no cooldown by default, whatever
`--cooldown` or the repository's Dependabot `cooldown.default-days` says,
because the risks differ from an action release:

- an allow-list release changes which endpoints a job may reach and runs
  no code of its own, and it grows far more often than it shrinks;
- in `lfreleng-actions/.github`, every allow-list change passes review
  and a block-mode probe workflow before anyone tags it;
- a stale pin is itself the failure: a block-mode job that lacks a
  newly allowed endpoint fails with `ECONNREFUSED` until the pin moves.

Dependabot's cooldown describes the `uses:` references it manages and
says nothing about these pins, which it cannot see. To hold allow-list
pins back anyway, set the window explicitly:

```bash
# Quarantine action releases for 7 days, take allow-list releases at once
gha-workflow-linter lint --action-calls update --cooldown 7 \
  --allow-list update

# Hold allow-list releases back for 7 days too
gha-workflow-linter lint --allow-list update --allow-list-cooldown 7
```

The configuration file key is `allow_list.cooldown_days`.

#### Suppressing a deliberate pin

A repository may hold a pin at an older version on purpose. The linter
accepts either of two forms:

<!-- markdownlint-disable MD013 -->

```yaml
    # gha-workflow-linter: allow-list-pin-ok -- waiting on ONAP rollout
    config: '@8f4f0cf83e6a015957e83261ed379fd811fc060e'  # v0.5.1

    config: '@8f4f0cf83e6a015957e83261ed379fd811fc060e'  # v0.5.1 allow-list-pin-ok
```

<!-- markdownlint-enable MD013 -->

The preceding-line form must sit on the line directly above the pin, at
any indentation. An optional reason may follow ` -- ` and appears in
reports. Both forms stay inert at run time: the action never sees them.

The linter excludes a suppressed pin from reporting, enforcement **and
remediation**: `--allow-list update` leaves it alone. It still lists it
under `--format json` with
`"suppressed": true`, and every run prints a one-line count so
suppressions stay visible.

Suppression covers **currency** and nothing else. A pin whose version comment
disagrees with its SHA, or whose spec breaks the grammar, counts as a
defect regardless of intent and stays reported.

#### Resolving the organisation

The `@<sha>` shorthand resolves its host organisation from the workflow's
own organisation. The linter infers this from `GITHUB_REPOSITORY_OWNER`,
then the `upstream` git remote, then `origin`. Contributors working from
a personal fork should pass `--allow-list-org` explicitly, since `origin`
would otherwise resolve to a `.github` repository that does not exist.

### Stderr Merge Checking

A command that merges stderr into stdout (`2>&1`, `&>`, `|&`, or any
command after `exec 2>&1`) and then parses, compares or exports the
result works until the tool prints a warning. Then the warning becomes
part of the data. In #187, `gerrit_query.sh` captured
`ssh … gerrit query --format JSON … 2>&1` and handed it to `jq`; one
SSH warning broke every consumer of `gerrit-change-info`.

The check reads shell offline and never calls the GitHub API, so it runs
under a rate limit and when no action calls exist to check:

```bash
# Report merges (the default); never fails the run
gha-workflow-linter lint --stderr-merge report

# Fail with exit status 8 on a high or medium finding
gha-workflow-linter lint --verify-stderr-merge

# Fail on low findings too
gha-workflow-linter lint --verify-stderr-merge --stderr-merge-min-confidence low

# Skip the check
gha-workflow-linter lint --stderr-merge off
```

It offers no `fix` or `update` mode: where stderr should go depends on
what the step does with it, so the fix needs a person.

#### Rules

<!-- markdownlint-disable MD013 -->

| Rule     | Reports                                                                                                                | Confidence | Suggested fix                                                       |
| -------- | ---------------------------------------------------------------------------------------------------------------------- | ---------- | ------------------------------------------------------------------- |
| `SEM001` | Merged stream piped into a structured parser (`jq`, `yq`, `base64 -d`, JSON through Python or Node)                    | high       | Send stderr elsewhere: `2>"$err"`, printed on failure, or the log   |
| `SEM002` | Merged capture whose variable the success path parses, compares, or writes to `$GITHUB_*`                              | high       | Capture stdout alone; keep stderr in a file for the error message   |
| `SEM003` | Merged stream piped into a field extractor (`cut`, `awk`, `sed -n`, `grep -o`, `read`), or captured and passed on      | medium     | As `SEM001`                                                         |
| `SEM004` | Merged stream used through `grep -q` or an anchored extraction, or from a command that writes its data to stderr       | low        | Merge when the tool writes the wanted text to stderr; else `SEM001` |

<!-- markdownlint-enable MD013 -->

The rule identifiers stay stable across releases. Enforcement counts
`high` and `medium` findings unless `--stderr-merge-min-confidence`
(or `stderr_merge.min_confidence` in the configuration file) sets
another floor. Display uses (`tee FILE`, `cat` or `head -N` to the
log, indentation through `sed`, and `head -1`, `sort` or plain `grep`
whose result is not captured, compared or parsed) and logging commands
(`echo`, `printf`, workflow commands, `logger`, and functions named
like `log_*` or `die`) do not count as data uses.

A capture keeps what every statement in it writes, the bodies of `if`,
`case` and loops included, and a value that `echo`, `printf` or `cat`
prints into another `$( )`, from any stage of a pipeline, stays
tracked. A pipeline stage that reads a here-string, here-document or
file of its own, as in `a 2>&1 | jq . <<< "$x"`, takes nothing from the
pipe.

A redirect on a group, a subshell, `if`, `case` or a loop reaches each
command in it, before that command's own redirects, as Bash applies
them: `{ tool 2>/dev/null; } 2>&1` merges nothing, while
`{ gh api x 2>&1; } | jq .` does, and `if …; fi >> "$GITHUB_OUTPUT"`
exports what its commands print. A runner file is a destination that
is the expansion and nothing else, as in `"$GITHUB_OUTPUT"` or
`${GITHUB_ENV}`; `logs/GITHUB_OUTPUT.log` and a single-quoted
`'$GITHUB_OUTPUT'` are ordinary files. The check sees through
`timeout`, `sudo`, `env`, `nice`, `stdbuf` and `command`, reading each
one's own options, so `sudo -n jq .` runs `jq`.

#### Success path and failure path

A capture used to explain a failure is correct: the command failed, and
its stderr is the explanation. The check reports a use of a merged
capture on the success path, and places each use lexically, within one
`run:` block or script function:

- `if ! VAR=$(…); then A; else B; fi`: `A` is the failure path.
- `if VAR=$(…); then A; else B; fi`: `B` is the failure path.
- `VAR=$(…) || A`: `A` is the failure path, as is `B` in
  `VAR=$(…) || A || B`.
- `VAR=$(…)`, then `S=$?`, then `if [ "$S" -eq 0 ]`: the zero branch is
  the success path and the other branches, `elif` included, the failure
  path. `-ne 0`, `!= 0` and a leading `!` turn that round. The test
  must be the `if`'s last condition, and `S` unwritten since `S=$?`.

Everything else counts as the success path, including code after the
`fi`, a status tested through a `test` command rather than `[ ]`, and a
capture or status test joined to another command by `&&` or `||`
(`if VAR=$(…) && check` runs its `else` when `check` fails after the
capture succeeded). A merged value stays tracked until an assignment
that always runs replaces it: one in a branch, after `||` or `&&`, or
in a subshell does not, nor does an append (`VAR+=…`). A capture made
inside a subshell or substitution stays there. An `exec 2>&1` inside a
subshell, substitution or function leaves the commands outside it
alone, and a later `exec 2>/dev/null` ends it. That over-reports by
design; the suppression directive covers the rest.

#### Commands that write their data to stderr

These need the merge, so the check caps them at `low` (`SEM004`):
`java -version` and `javac -version`, python's own `-V` and
`--version` (not ones after the script, `-c` or `-m`),
`ldd --version`, `ssh -V`, `mkcert -version`, `openssl s_client`,
`nc -z` and `nc -v`, and `docker logs` or `podman logs`. The cap
applies through a container or remote launcher too: `docker exec`,
`docker run`, `podman exec` and `podman run`, `kubectl exec` with its
command after `--`, and `ssh` with one simple remote command (limit 3
sets out the grammar), so the cap
covers `docker exec box openssl s_client` while
`docker exec box curl x` keeps its rating. The cap is
the command's own: a capture that also holds a merge from another
command, as in `v=$(python3 -V 2>&1; gh api x 2>&1)`, reports the
other command's finding.

#### Scope and limits

The check targets the common, data-bearing merge that broke
`gerrit-change-info` and its siblings. It reads each command's literal
words against fixed tables; it does not interpret bash. These limits
are deliberate:

1. **Fixed tables.** The check classifies consumers by name: parsers (`jq`,
   `yq`, `xq`, `tomlq`, `xmllint`, `base64 -d`, Python or Node reading
   JSON), extractors (`awk` and its variants, `cut`, `read`, `mapfile`,
   `readarray`, `xargs`, `sed` with `-n` or a `p` flag, `grep -o`),
   pickers (`grep`, `head` or `tail` taking one line, `sort`, `uniq`),
   an existence test (`grep -q`), pass-through (`tee`, `cat`) and
   loggers (`echo`, `printf`, `logger`, `:`, `true`, `exit`,
   `return`). Options match their common spellings (`-n 1`,
   `--lines=1`). Beyond `grep`'s `--`, `-e` and `-f`, the check does
   not parse each tool's option grammar: attached operands and option
   clusters get no special handling.
2. **Commands outside the tables.** A merged stream piped into an
   unlisted command goes unreported. A merged capture passed as an
   argument to one reports `SEM003` at `medium`.
3. **Wrappers.** The check looks through `timeout`, `sudo`, `env`,
   `nice`, `stdbuf` and `command`. It looks through container and
   remote launchers (`docker exec`, `docker run`, `podman exec`,
   `kubectl exec`, `ssh`) to apply the `low` cap above, and for no
   other purpose, reading each launcher's common options. The
   look-through follows a fixed grammar, and a launcher outside it
   keeps its own rating:
   - `ssh` counts when its remote program is one simple command alone:
     a list, pipeline, subshell, substitution or redirect, as in
     `ssh host 'openssl s_client; curl x'`, keeps the launcher's
     rating.
   - `docker` or `podman` with `--entrypoint CMD` or
     `--entrypoint=CMD` keeps the launcher's rating, since the
     entrypoint, not the words after the image, runs.
   - `docker` or `podman` with `-d` (also in a cluster such as `-dit`)
     or `--detach` keeps the launcher's rating, since the capture
     holds the container ID.

   No other launcher option changes the result. A command the
   launcher runs through a shell, as in `docker exec box sh -c '…'`,
   takes the rating of its use. Suppress it with a reason.
4. **Anchored extraction** (`SEM004`) rests on the pattern: a `grep`,
   `awk` or `sed` pattern anchored at the start of the line. The check
   does not examine options such as `grep -v`, `-A`, `-B` or `-C`, nor
   programs that move on to another line (`sed`'s `n`, `awk`'s
   `getline`). An address range such as `/^{/,/^}/` is not anchored:
   it selects every line between its ends.
5. **No descriptor or variable state.** The check assumes every command
   runs as written. It does not model closed or redirected stdin
   (`exec 0>&-`, `<&-`, `/dev/stdin` and `/dev/fd/*` aliases),
   `readonly` variables, or a command that would fail on an invalid
   option. Such cases over-report.
6. **Lexical paths.** The success and failure paths above are lexical,
   within one `run:` block or script function, and over-report when in
   doubt.

A request to model more of bash than this falls outside the check's
scope. A miss in real code, with the script that caused it, belongs in
an issue, and the suppression directive covers a deliberate merge.

#### Suppressing a deliberate merge

Both forms `allow-list-pin-ok` accepts work here:

```yaml
    run: |
      # gha-workflow-linter: stderr-merge-ok -- the tool prints JSON on stderr
      out=$(tool --json 2>&1)
      tool --json 2>&1 | jq .  # stderr-merge-ok
```

On a one-line `run:` value, the inline form may also be a YAML comment
after the value, which YAML keeps out of the shell:
`run: 'tool 2>&1 | jq .'  # stderr-merge-ok -- reason`.

A suppressed finding never fails the run. The text report counts
suppressed findings, `--show-suppressed` lists them with their
reasons, and the JSON document carries them with `"suppressed": true`.

#### Context tags

Each finding carries the tags of its file, naming what a defect there
puts at risk: `action` for composite action metadata, since a defect
breaks every caller, and for workflows `workflow_call`,
`pull_request_target`, `workflow_run`, `secrets`, `write-permissions`
and `no-checkout`.

### Python Path Checking

A Python or uv run in CI that takes in files from the workspace runs
whatever a pull request put there. `python -m tool` puts the working
directory first on `sys.path`, so a `tool.py` or `json/` directory in
the checkout replaces the module the step meant to run. `PYTHONPATH`
naming the checkout, and uv reading the workspace's `.python-version`
or `.venv`, do the same for the interpreter and its packages
(lfreleng-actions/.github#337 fixed these patterns across the
organisation).

The check reads the `run:` steps of workflows and composite actions,
and shell scripts, offline. It never calls the GitHub API, so it runs
under a rate limit and when no action calls exist to check:

```bash
# Report findings (the default); never fails the run
gha-workflow-linter lint --python-path report

# Fail with exit status 7 on a finding of PPA001 to PPA008, or of
# PPA011 to PPA013 in a composite action
gha-workflow-linter lint --verify-python-path

# Skip the check
gha-workflow-linter lint --python-path off
```

It offers no `fix` or `update` mode: which interpreter a step should
run, and with which flags, needs a person.

#### Python path rules

<!-- markdownlint-disable MD013 -->

| Rule     | Reports                                                                  | Suggested fix                                                                                                      |
| -------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| `PPA001` | python -m without -I: the working directory leads sys.path               | Add `-I`: `python3 -I -m tool`                                                                                     |
| `PPA002` | python -c without -I: the working directory leads sys.path               | Add `-I`: `python3 -I -c '…'`                                                                                      |
| `PPA003` | python reading stdin without -I: the working directory leads sys.path    | Add `-I`: `python3 -I - <<'EOF'`                                                                                   |
| `PPA004` | PYTHONPATH may hold an empty entry                                       | Join entries without a leading, trailing or doubled `:`                                                            |
| `PPA005` | PYTHONPATH names the caller's checkout                                   | Point `PYTHONPATH` at the action's own files, not the workspace                                                    |
| `PPA006` | uv reads .python-version from the workspace                              | Pass `--no-config`, or request an interpreter with `--python`                                                      |
| `PPA007` | uv uses a .venv in the workspace                                         | `uv run`: pass `--no-project` and a `--python` path outside the workspace; `uv pip`: pass a trusted `--python`     |
| `PPA008` | setup-uv works in the workspace                                          | Set `working-directory` to `${{ github.action_path }}` or `${{ runner.temp }}`                                     |
| `PPA009` | unresolved: the command's effect depends on a value the scan cannot read | A notice: confirm the value by hand, or suppress it with a reason                                                  |
| `PPA010` | not fully scanned: shell the parser could not read                       | A notice: simplify the shell, or suppress it with a reason                                                         |
| `PPA011` | setup-uv runs an interpreter the caller's environment chooses            | Use the guarded step in [setup-uv and the caller's environment](#setup-uv-and-the-callers-environment)             |
| `PPA012` | setup-uv adds a directory from the caller's environment to PATH          | Set `tool-bin-dir` under `${{ runner.temp }}` or `${{ github.action_path }}`, as the guarded step does             |
| `PPA013` | uv chooses its interpreter from the caller's environment                 | Pass a [trusted interpreter](#trusted-interpreter-values) as `--python`; run `uv python find` under `env -i`       |

<!-- markdownlint-enable MD013 -->

The rule identifiers and messages come from the scan engine and stay
stable across releases. Each finding names its file's `kind`:
`action` for composite action metadata, `workflow`, or `script`.

#### setup-uv and the caller's environment

A composite action inherits its caller's job environment, so an
earlier step of that job, through `$GITHUB_ENV` or `$GITHUB_PATH`, can
choose what an `astral-sh/setup-uv` step in the action runs. `PPA011`
and `PPA012` judge each setup-uv step from its own `with:` inputs and
step `env:`, and, in a composite action, from the text of the earlier
`run:` steps, with no shell analysis.

uv 0.13.5 reads these variables to choose an interpreter, as the
Evidence section of #448 records them:

- `PATH`
- `UV_PYTHON`
- `UV_PYTHON_SEARCH_PATH`
- `VIRTUAL_ENV`
- `CONDA_PREFIX`
- `CONDA_DEFAULT_ENV`
- `CONDA_ROOT`
- `UV_INTERNAL__PARENT_INTERPRETER`
- `UV_INTERNAL__TEST_PYTHON_MANAGED`
- `PYTHONEXECUTABLE`
- `__PYVENV_LAUNCHER__`
- `UV_SYSTEM_PYTHON`
- `UV_MANAGED_PYTHON`
- `UV_PYTHON_PREFERENCE`
- `UV_PROJECT_ENVIRONMENT`

Check this list against the uv release a step installs: a later
release can read more. `INTERPRETER_SELECTORS` in
`src/gha_workflow_linter/python_path/_uv.py` holds this list, and
`PPA013` reads it from there.

The rules rest on these facts about setup-uv v10.3.3, which a reader
can check against later uv and setup-uv releases:

1. With the inputs below, `uv python find` is the one uv call
   setup-uv makes, and it executes the interpreter that call
   returns. A `UV_PYTHON_PREFERENCE` value uv does not accept makes
   uv refuse its arguments before any lookup; setup-uv then reports
   the Python version as `unknown`.
2. An inherited `UV_PYTHON_ARCH` makes setup-uv probe uv, so the step
   sets it to `''`; the `python-arch` input does the same.
3. With the cache on, the post-step runs `uv cache prune`.
4. `activate-environment` creates and activates a virtual environment
   with uv, and `python-version` exports `UV_PYTHON` to later steps of
   the caller's job.
5. With `UV_NO_MODIFY_PATH` set, to any value, setup-uv leaves its own
   uv off `PATH` but still starts a bare `uv python find`, so the
   caller's `PATH` picks the uv that runs. A step cannot unset an
   inherited variable: this repository's Action refuses to run.
6. Without `tool-bin-dir`, setup-uv adds a bin directory from the
   caller's `HOME` or `XDG_*` settings to `PATH`.
7. setup-uv adds `UV_PYTHON_INSTALL_DIR` to `PATH` after its own uv,
   and `core.addPath` prepends, so an inherited directory sits ahead
   of the downloaded uv when setup-uv starts a bare `uv python find`.

The guarded step, with the refusal step ahead of it, as this
repository's own `action.yaml` writes them:

```yaml
- name: "Refuse an inherited UV_NO_MODIFY_PATH"
  shell: bash
  run: |
    if [[ -n "${UV_NO_MODIFY_PATH+set}" ]]; then
      echo "::error::Unset UV_NO_MODIFY_PATH before this action"
      exit 1
    fi
- uses: astral-sh/setup-uv@68559e99cc807c1eb7e9238fd43a15bba460eec2  # v10.3.3
  with:
    working-directory: ${{ github.action_path }}
    tool-bin-dir: ${{ runner.temp }}/my-action/bin
    enable-cache: false
  env:
    UV_NO_CONFIG: "1"
    UV_NO_PROJECT: "1"
    UV_PYTHON_PREFERENCE: "lookup-disabled"
    UV_PYTHON_ARCH: ""
    UV_PYTHON_INSTALL_DIR: ${{ runner.temp }}/my-action/python
```

`PPA011` reports a setup-uv step unless each of these holds, and names
the first that fails:

- step `env` sets `UV_PYTHON_PREFERENCE` to a literal outside the four
  valid values;
- step `env` sets `UV_PYTHON_ARCH: ''`, and the `python-arch` input is
  absent;
- `enable-cache` is the literal `false`;
- `activate-environment` is absent or `false`;
- the step does not set `UV_NO_MODIFY_PATH`, and, in a composite
  action, an earlier `run:` step of the same file refuses an inherited
  one: its text names `UV_NO_MODIFY_PATH` and contains `exit 1`.
  Otherwise the finding says the caller may pass it. In a workflow the
  step alone decides, since a job's environment is its own;
- step `env` sets `UV_PYTHON_INSTALL_DIR` under `${{ runner.temp }}`
  or, in a composite action, `${{ github.action_path }}`, with no
  `PATH` separator or line break; otherwise the finding says it comes
  from the caller.

A step with `python-version` in place of the invalid preference
reports that it exports `UV_PYTHON` to later steps of the caller's
job, and one that sets `UV_SYSTEM_PYTHON` adds that uv searches
`PATH`. A `${{ }}` expression fails its condition, since the scan
cannot read it, and the finding says so.

`PPA012` reports a setup-uv step whose `tool-bin-dir` is absent, holds
a `PATH` separator or a line break, or does not lie under
`${{ runner.temp }}` or, in a composite action,
`${{ github.action_path }}`. setup-uv expands no shell variable in
the input, so `$RUNNER_TEMP/bin` names a directory below the working
directory and the check reports it, as it does any other expression,
such as `${{ env.UV_TOOL_BIN_DIR }}`: a composite action's `env`
context is the caller job's. The check matches `with:` input names in
any case, as setup-uv reads them; see **Scope and limits** for how
it reads step `env:` names.

#### uv commands and the caller's environment

`PPA013` reports a uv command in a workflow or composite action whose
interpreter the caller's environment can choose. It does not read
scripts, whose caller the scan does not know. Three cases count:

1. **Rule 1.** `uv run`, `uvx`, `uv tool run`, `uv venv`, `uv sync`,
   `uv export` and `uv pip` discover an interpreter. Without a
   trusted `--python` or `UV_PYTHON` the caller's `UV_PYTHON`,
   `VIRTUAL_ENV`, `CONDA_PREFIX` or `PATH` picks it. A version such
   as `--python 3.12` is a request, not a path; `--system`,
   `UV_SYSTEM_PYTHON`, `--managed-python` and `UV_MANAGED_PYTHON`
   leave the search to the caller too, so `uv pip --system` clears
   `PPA007` alone. A `--python` or `UV_PYTHON`
   value the scan cannot trace to a trusted interpreter is `PPA009`.
   `env -u UV_PYTHON` (`--unset`, `-uNAME`) removes the step's value
   from the command, so a trusted step `env:` `UV_PYTHON` no longer
   pins it; a `NAME=value` after the `-u` sets it again. An `env -u`
   operand the check cannot read may name any setting, so no value
   set before it, by a wrapper's `NAME=value` included, pins one.
2. **Rule 2.** `uv python find` and `uv python install` read `PATH`
   and `UV_*` from the caller unless `env -i` (or `env -`) runs them.
   `env -u` or a `NAME=` value the check cannot read is `PPA009`, and
   does not hide this finding: the caller's environment still
   reaches uv.
3. **Rule 3.** `UV_PYTHON`, `UV_SYSTEM_PYTHON` or `UV_MANAGED_PYTHON`
   set in a workflow, job or step `env:` block, or written to
   `$GITHUB_ENV`, reaches every uv command that inherits it. A
   `UV_PYTHON` holding a trusted interpreter is fine; the check reads
   these names in any case, as Windows does. The check reads a
   `$GITHUB_ENV` write by record, as the runner does: a line inside
   another variable's `NAME<<DELIMITER` record sets nothing, and a
   `UV_PYTHON<<DELIMITER` record holds one value. A write whose format
   or name the check cannot read (`printf "$fmt"`, `printf '%b'`)
   and whose text names one of these settings is `PPA009`. An
   unquoted reference in such a write (`echo UV_PYTHON=$PY`, or
   `$PYTHONPATH` itself) holds a trusted
   interpreter as far as **Word splitting** allows, as in a
   `$GITHUB_OUTPUT` write.

A command that `env -i`, `env -`, `exec -c` or `sudo` runs gets no
`PPA013`, unless the wrapper keeps one of the interpreter selectors
[listed above](#setup-uv-and-the-callers-environment) or a `UV_*`
name, or passes a selector itself as `NAME=value` (see **Python path
scope and limits**): the caller's environment does not reach it.

#### Trusted interpreter values

`PPA013` and the program checks of the other rules trust these as an
interpreter:

- an absolute literal path outside the workspace, such as
  `/usr/bin/python3`;
- `${{ steps.<id>.outputs.python-path }}` of an
  `actions/setup-python` step earlier in the same job;
- a run step's output, `${{ steps.<id>.outputs.<name> }}`, that the
  step writes once to `$GITHUB_OUTPUT` from a variable it assigns
  once from `$(env -i … uv python find …)` with
  `--managed-python`, or with `--system` and `--no-config`;
  `uv python install` is not a lookup, and its output is never
  trusted;
- a shell variable assigned once at the top level of the step, or a
  step `env:` value, that holds one of the above;
- a double-quoted word composed of literal text and references, such
  as `"${ENV_DIR}/${BIN}"`, whose every value is a trusted
  interpreter (see **Composed words**).

`${{ steps.<id>.outputs.uv-path }}` of an `astral-sh/setup-uv` step
earlier in the job counts as uv, so `"$UV" pip install --python
"$PYTHON"` reads as a uv command. A step id used twice, an output
written twice, a variable assigned twice, or a step that runs `eval`,
`source` or `.` trusts nothing; nor does a producer step with an
`if:` or a `continue-on-error:` other than `false`, whose output may
be empty. A Python-named expression none of these produces, such as
`"${{ inputs.python }}" -I s.py`, is `PPA009` as a program; the check
still judges how it runs Python. The trust is lexical: the check does
not follow functions, loops or conditionals, beyond the unset filters
and loop appends that **Python path scope and limits** names. Quote
the reference: `"$PYTHON"` holds one word, while an unquoted
`$PYTHON` from a step output may split, so the check reads it as
`PPA009`.

#### Suppressing a deliberate run

Both forms `stderr-merge-ok` accepts work here, on the line above the
command or as a comment after it:

```yaml
    run: |
      # gha-workflow-linter: python-path-ok -- the module ships in this repository
      python3 -m tools.release
      python3 -c 'import sys'  # python-path-ok
```

The check reads comments as the shell reads the step: a `#` inside a
shell string, multi-line or ANSI-C (`$'...'`) included, is text, while
one inside a quoted YAML `run:` value starts a shell comment. When a
quoted one-line `run:` value carries a shell comment and a YAML comment
follows it, a directive in either counts. A shell comment covers its
own step and no other: where steps share a line, as in a flow
sequence, a YAML comment after them covers each one, and a comment
that ends one step's `run: |` block does not reach the next step's
line. Outside
the shell, a `#` inside any other YAML value, a block or quoted
`name:` or `env:` value for one, is text. The form on the line above
counts where a comment starts that line, and not where the line sits
inside a shell string or a YAML value. A suppressed finding never
fails the run. The text report counts suppressed findings,
`--show-suppressed` lists them with their reasons, and the JSON document
carries them with `"suppressed": true`. The engine's own
`python-path-audit: ignore` mark still drops a finding entirely.

#### Python path failures and exit codes

Without `--verify-python-path` the check reports and leaves the exit
code alone. With it, an unsuppressed finding of `PPA001` to `PPA008`,
or of `PPA011` to `PPA013` in a composite action, makes the run exit
`7`, and a file the check could not read makes it
exit `1`: enforcement that never looked must not pass. A check that
fails outright does the same under `--verify-python-path`, and
otherwise logs the failure and lets the run continue.

`PPA009` and `PPA010` never fail a run, with or without
`--verify-python-path`. They mean "the scan could not prove this
safe", not "this is unsafe": most are the hardened pattern itself,
an interpreter held in a variable such as `"$PYTHON" -I script.py`.
The text output labels them `notice`, and the Action annotates them
as notices. The Action annotates the other rules as errors whenever
the run enforces the check, whether the `verify-python-path` input or
the configuration file turned it on, and as warnings otherwise. It
names each file from the workspace root, so a scan of a subdirectory
annotates the right file.

#### Python path scope and limits

1. **Notices never fail.** The check reports `PPA009` and `PPA010` but
   never fails a run on them.
2. **Unread values.** The check reports an interpreter reached
   through a value it cannot read, such as a step output or an
   unknown variable, as `PPA009`, without judging it.
3. **The caller's environment.** `PPA011` and `PPA012` cover a
   setup-uv step the caller's environment can steer, and `PPA013` a
   uv command. #448 tracks the bare-`python` rule. The `PPA011`
   guard list follows the source of setup-uv v10.3.3 and may need
   revisiting for a later release. The rules read a step's values
   this way:
   - **Trimming.** A `with:` value loses its leading and trailing
     white space and line breaks, as `core.getInput()` trims it, so
     `'false '` and a block scalar's final newline count as setup-uv
     reads them. A step `env:` value stays as written: uv reads it so.
   - **Separators.** A `tool-bin-dir` whose literal text holds `:`,
     `;` or a line break is a `PPA012` finding wherever it starts:
     setup-uv would add more than one directory to `PATH`. Such a
     `UV_PYTHON_INSTALL_DIR` fails its `PPA011` guard the same way.
   - **Expressions.** A `${{ }}` value is one the scan cannot read, so
     it fails its condition; `tool-bin-dir` and
     `UV_PYTHON_INSTALL_DIR` must start with `${{ runner.temp }}` or
     `${{ github.action_path }}`.
   - **Literal paths.** A literal `tool-bin-dir` or
     `UV_PYTHON_INSTALL_DIR` fails these two guards even when absolute:
     on Windows `/a/repo/repo/bin` lands in the checkout.
   - **Windows paths.** A step may run on Windows, which
     splits a path on `\` as well as `/`, so a `tool-bin-dir` or
     `UV_PYTHON_INSTALL_DIR` with a `..` component between either
     slash, such as `${{ runner.temp }}/..\repo\bin`, counts as
     outside.
   - **Refusal step.** The check matches the step that refuses an
     inherited `UV_NO_MODIFY_PATH` by its text alone: a `run:` step
     before the setup-uv step, in any shell, that names the variable
     and contains `exit 1`. It does not prove that the step refuses
     the variable, or that it runs.
   - **Name case.** Windows reads environment names in any case,
     Linux as written. A step `env:` name that weakens the step,
     `UV_NO_MODIFY_PATH` or `UV_SYSTEM_PYTHON`, counts in any case. A
     guard needs its exact name, and fails when the step also sets it
     in another case, since the platform then decides which value uv
     reads.
4. **The trusted model.** [Trusted interpreter
   values](#trusted-interpreter-values) rest on these readings:
   - **Output writes.** A `$GITHUB_OUTPUT` write counts when its
     standard output goes there: an unnumbered, `1>` or `1>>`
     redirect, or `&>` and `&>>`. `2>>` does not, nor a later
     redirect that sends fd 1 elsewhere (`> /dev/null`, `>&2`); a
     mention of `GITHUB_OUTPUT` the check does not read as a write
     makes it trust no output of the step. So does a write inside a
     conditional, loop, function, `&&` or `||` list, or subshell,
     which may never run: a write must stand at the top level.
   - **Producers.** A step with an `if:`, or a `continue-on-error:`
     other than `false`, gives no trusted output: it may not run, or
     may fail, and leave the output empty.
   - **Assignments.** `eval`, `source` and `.` count in any
     spelling: quoted, or after `builtin` or `command`; so does a
     `trap` that sets an action, whose text may run before any
     command. `printf -v`,
     `read`, `unset`, `export` and the other assigning builtins count
     their targets after quote removal (`printf -v "PY"` assigns
     `PY`). `read` and `select` always count `REPLY`, and `mapfile`
     and `readarray` `MAPFILE`, the names they fill when given none.
     `printf` counts its arguments as targets when its format holds
     `%n` or is not literal. A target the check cannot read
     (`read -r "$DEST"`, `printf -v "$DEST"`, `export "$NAME"`,
     `unset "$NAME"`) may name any variable, so the step trusts none,
     with one exception: an `unset "$name"` that a `case` arm or a
     `grep -E` feed filters (see **Unset
     filters**) removes the names its filter matches and no others.
     A subscript write (`PY[1]=x`) changes `PY` but never binds
     `"$PY"`. A step `env:` `UV_PYTHON` the step assigns, unsets or
     leaves opaque gives uv no exemption: `PPA009`. A `NAME=value`
     on the uv command or its wrapper still decides.
   - **Values.** A value holding a line break or other control
     character is not one path and is never trusted: written to
     `$GITHUB_OUTPUT` it would start a second record. An output
     written from a literal path stands for that path, so its name
     decides whether a later step runs Python or uv.
   - **Word splitting.** An unquoted reference, in a command or a
     `$GITHUB_OUTPUT` write, resolves when it holds a literal value
     with no blank or glob character, in a step that never sets
     `IFS`; a quoted `"$PYTHON"` always resolves. A value traced to
     an expression, such as a setup-python path or a
     `${{ runner.temp }}/…` path, holds text the check cannot see, so
     an unquoted reference to it never resolves. A variable, a
     composed word such as `"${ROOT}/pypy3"`, or a step output
     substituted in a command, that resolves to a path whose name is
     neither Python nor uv, such as `/opt/pypy3`, stays `PPA009`
     when the command looks like Python.
   - **Unset filters.** `unset NAME` with literal names changes
     those names alone. `unset "$name"` removes the names a filter
     allows, and no others, when it stands alone in one of two
     places: a
     `case "$name"` arm of plain globs (letters, digits, `_`, `*`,
     `?`), less any name an earlier arm matches, with no `;&` or
     `;;&` and no `nocasematch` in the step; or the body of `while
     [IFS=] read -r name; do …; done < <(… | grep -E 'RE')`, with
     at most `|| true` after the `grep`, which removes the names `RE`
     matches. `RE` holds nothing but letters, digits and
     `_.+*?|()^$`, with no two of `+*?` in a row (Python reads
     `++` as possessive and `+?` as lazy, where `grep` repeats the
     repetition), and the `grep` takes no `-v` or other option.
     Without `-r`, `read` drops backslashes from the line `grep`
     matched, so the loop may remove any name. `read` strips `IFS`
     characters from that line too, so without `IFS=` before it, in a
     step that sets `IFS`, the loop may remove any name. The target
     must be double-quoted in either place: bash splits an unquoted
     `$name` on `IFS` and globs it, so `PYTHONX` under `IFS=X`
     unsets `PYTHON`, and the step trusts none. A variable
     the filter may match counts as changed. Any other `unset` target
     the check cannot read trusts nothing.
   - **Composed words.** A double-quoted word of literal text and
     references, such as `"${ENV_DIR}/${BIN}"`, takes every value its
     parts may hold, up to 16: a reference's trusted value, or, for a
     name the step never sets, each literal its step `env:` value
     `${{ COND && 'A' || 'B' }}` may give. `COND` may hold no `&`,
     `|` or parenthesis outside quotes. Text between the parts, a
     line break included, is part of every value. The check trusts
     the word, assigned to a variable or used directly as a command
     argument, when each value is a trusted interpreter; when the
     word has more than one value, or its one value ends `.exe`, each
     must name Python (`python`, `python3`, `python3.12`, with or
     without `.exe`).
   - **Path expressions.** A step `env:` value that is a lone
     `${{ github.action_path }}`, `${{ github.workspace }}` or
     `${{ runner.temp }}` reads, quoted as `"$V"` in a step that
     never sets `V`, as the inline expression would; in a workflow,
     which has no action path, `${{ github.action_path }}` does not.
     A value starting `${{ runner.temp }}/` with literal text alone
     after it, and no empty, `.` or `..` component between either
     slash, is a path outside the workspace.
   - **Lookups.** The check trusts the result of `env -i … uv python
     find` when the lookup passes `PPA006` and `PPA007`
     itself: with `--managed-python`, or with `--system` and
     `--no-config` (or `UV_NO_CONFIG=1`). A lookup that could return
     a workspace `.venv` gives no trusted value. A `uv python find
     --managed-python` lookup is not `PPA007`: the option keeps uv to
     its own installs. Nor is `uv export --script`, which exports the
     script's requirements rather than a project's. `uv python
     install` prints no path on some uv releases, so its output is
     never trusted. The version request may be `"$V"` for a step
     `env:` value of literal text the step never sets. In a leaf uv
     subcommand such as `uv venv` or `uv sync`, a later word is an
     operand, not a subcommand. An operand the check cannot read
     may still expand to an option such as `--python=…`, so it stays
     `PPA009` unless the whole word is one double-quoted string that
     opens with a path expression, such as `"${DIR}/v"` for a step
     `env:` `DIR` of `${{ runner.temp }}`. As on the check's earlier
     releases, it reads the first operand alone: a later one that a
     caller's input expands to an option is outside the model.
   - **Cleared wrappers.** `env -i`, `env -`, `exec -c` or `sudo`
     loses its exemption when any `NAME=value` it passes, through
     nested wrappers and after `sudo` included, names an interpreter
     selector. These names, which the pinned lookup of
     lfreleng-actions/pypi-version-check-action#181 needs, may pass:
     `PATH`, `HOME`, `UV_NO_CONFIG`, `UV_PYTHON_INSTALL_DIR`,
     `UV_CACHE_DIR` and `UV_NO_PROGRESS` (`CLEARED_ALLOWED` in
     `_uv.py`), each with a literal value: `PATH="$PATH"` or a
     `${{ }}` value counts as a passed selector. A passed `UV_PYTHON`
     holding a trusted interpreter still pins uv. The `env -i`
     array may be a literal `NAME=value` array, extended by a top-level
     `for name in A B C; do … clean+=("$name=${!name}"); done` over
     literal names: each name passes with the caller's value, which
     the check cannot read. A name outside the selectors, such as
     `HTTPS_PROXY`, may pass so; an interpreter selector, or one of
     the allowed names above, which need a literal value, drops the
     exemption. A
     `${{ runner.temp }}/…` value counts as literal here. Such an
     array serves the trust of the lookup alone: when the check
     cannot resolve the program after it, such as `"$UV"` from a
     setup-uv step with an `if:`, the command reads as if the array
     were unread too, as on the check's earlier releases.
   - **Indirect reads and assignments.** An indirect read
     (`${!name}`) assigns nothing: it never makes a step opaque, and
     a variable bound in step `env:`, such as `UV`, keeps its
     verdict. The value it reads is one the check does not follow.
     An indirect assignment (`printf -v "$name"`, `read "$name"`,
     `declare "$name=…"`, `eval`) may name any variable, so the step
     trusts none, as **Assignments** says.
   - **Trusted interpreter values: limits.** The model is lexical
     and fixed. It trusts a value through these alone: one unconditional
     top-level assignment, or one unconditional top-level
     `$GITHUB_OUTPUT` write, from a producer step without `if:` or
     `continue-on-error:`; a double-quoted expansion, or an unquoted
     one as **Word splitting** allows; the assigning builtins named
     above; and the selector constant above for `env -i`. It models no
     control flow beyond the unset filters and loop appends above, no
     functions, no arrays beyond the literal `env -i` form, and no
     `eval`, `source` or arithmetic. Anything else is `PPA009`,
     reported and never trusted. A request to model more of bash than
     this is out of the check's scope.

     This list is the whole model. A construct it does not name, such
     as arithmetic, indirect expansion (`${!name}`) outside the
     cleared-array loop above, `declare -n`, traps, co-processes,
     process substitution other than an unset filter's feed, or a
     value that crosses
     a step through any channel other than `$GITHUB_OUTPUT`, leaves the
     value unresolved: `PPA009`, reported and never trusted. A request
     to model more of bash than this falls outside the check's scope.
     The model fails closed: a value the check cannot read never earns
     an exemption or keeps a trust: a wrapper's `NAME=value`, a
     substituted step output, a `$GITHUB_ENV` write or an assigning
     builtin's target alike.
5. **Workflow findings do not gate.** In a workflow file the linter
   reports `PPA011` to `PPA013` but they never fail a run: a job
   sees its own environment. `PPA011` and `PPA012` do not read a
   `$GITHUB_ENV` write earlier in the same job; `PPA013` reports one
   that sets a uv interpreter setting.
6. **Out of scope.** The check does not read `.pth` files or Python
   source files.

### What Gets Scanned

The linter walks the tree below the path you give it, collecting
`.github/workflows/*.y{a,}ml` at any depth plus `action.y{a,}ml` files.

Scanning **stops at nested repository boundaries**. Git worktrees,
submodules and vendored clones each place a `.git` entry at their own
root, and anything beneath one belongs to a different repository, or to
a second checkout of this one. A repository that keeps worktrees under
`.worktrees/` would otherwise report every finding once per checked-out
branch, against files the working tree does not contain.

The scan root itself never counts as a boundary, so pointing the linter
at a worktree scans that worktree. Pointing it at a directory that
merely *contains* repositories finds nothing, since each child is a
boundary.

The stderr-merge and python-path checks read more: the `run:` steps of
workflows and composite actions, and shell scripts (`*.sh`, `*.bash`,
and files with no extension whose shebang names a shell). They honour
`--exclude` and `.gitignore`, never entering an excluded or ignored
directory, skip virtual environments, caches and `node_modules`, and
stop at the same nested repository boundaries. A file named with
`--files`, by a relative or absolute path or glob, gets scanned
whatever its name and wherever it lies.

### Multi-Repository Mode

`--multi-repo` treats the given path as a container of git repositories
and visits each in turn:

```bash
# Audit every checkout under a directory
gha-workflow-linter lint ~/Repositories/lfreleng-actions --multi-repo

# Fail if anything anywhere is stale
gha-workflow-linter lint ~/Repositories --multi-repo --verify-allow-list

# Bulk remediation across the estate
gha-workflow-linter lint ~/Repositories --multi-repo --allow-list update
```

A directory counts as a repository when it holds a `.git` entry, so
clones, worktrees and submodules all qualify. `--repo-depth` controls how
far below the path to look, defaulting to one level. Discovery stops at
each repository rather than descending into it, so a checkout keeping
worktrees under `.worktrees/` gets one visit, not one per branch.

Pointing the linter at a repository with `--multi-repo` visits that
repository alone, so the flag is safe to leave in a wrapper script.

#### Why this rather than a shell loop

The sweep builds one cache and shares it, so repositories pinning the
same allow-list host share a single latest-release lookup.
Twenty repositories cost one query rather than twenty.

That sharing stops under a non-default release policy. An allow-list
cooldown targets an older release by design, and prerelease eligibility changes
which releases count as candidates; the cache records the target and
the releases ranked behind it, but not which policy chose them, so a
cached answer cannot say whether it means the same thing to the next
reader. Rather than let one repository's policy leak into another's, the
sweep repeats the lookup per repository — twenty such repositories cost
twenty queries. Correctness wins over the saving here, and the saving
returns as soon as the default policy applies.

One host is also resolved afresh when a pin sits on a release the cached
entry never saw — the entry names the newest release at the moment of
writing, and anything else may have advanced the pin inside the cache
TTL. Trusting it there would report a current pin as stale and rewrite it
backwards. A pin the cached entry can place still costs nothing.

Each repository still gets its own workflow organisation and its own
Dependabot cooldown for action calls, since both belong to the repository
rather than to the sweep. The allow-list cooldown is the same for every
repository: the value from `--allow-list-cooldown` or the configuration
file, `0` by default.

#### Failures and exit codes

The sweep visits repositories one at a time, and one failing does not
stop the others: it records the failure, carries on, and closes with a
table listing every repository, its pin counts and its status.

| Status         | Meaning                                              |
| -------------- | ---------------------------------------------------- |
| `clean`        | Nothing outstanding                                  |
| `updated`      | The run rewrote something, leaving nothing to do     |
| `findings`     | Something needs attention                            |
| `unresolved`   | A host did not resolve, leaving the check incomplete |
| `rate-limited` | GitHub throttled the API, so the checks did not run  |
| `scan failed`  | A shell check could not read a file, or failed       |
| `failed`       | The sweep could not scan the repository              |

`unresolved`, `rate-limited` and `scan failed` get their own labels
because an incomplete check says nothing about the repository: its counts
are empty for want of an answer, not for want of a problem. `rate-limited`
and `scan failed` appear whatever the exit code, since an advisory sweep
still exits `0`. `scan failed` covers the stderr-merge and python-path
checks, with or without `--verify-stderr-merge` or `--verify-python-path`.

What remains outranks what the run achieved, so a partial remediation —
some pins rewritten, others still stale — reports `findings` rather than
`updated`. Reading `updated` means the repository needs no further
attention.

The exit code is the most significant across the sweep, following the
precedence in [Exit Codes](#exit-codes). A configuration error is the one
exception: a bad setting applies to every repository, so it stops the run
rather than repeating once per checkout.

#### JSON output

`--multi-repo --format json` emits a single document covering the whole
sweep, rather than one object per repository:

```json
{
  "error": null,
  "repositories": [
    {
      "repository": "example-workflows",
      "exit_code": 3,
      "error": null,
      "write_failures": 0,
      "autofix_error": null,
      "results": {
        "rate_limited": false,
        "error": null,
        "scan_summary": {},
        "allow_list": {}
      }
    }
  ],
  "summary": {
    "repositories": 1,
    "failed": 0,
    "rate_limited": false,
    "exit_code": 3
  }
}
```

A repository the sweep could not scan carries its reason in `error`, so a
failure stays distinguishable from a clean result. An empty container
still emits a document, for the same reason.

The **top-level** `error` reports a sweep that failed before it examined
anything — an unreadable container, or a depth it could not use. Without
it that document is identical to one describing a container that holds no
repositories at all.

`summary.rate_limited` reports whether the API throttled the sweep. It
sits in the summary as well as in each repository's `results` because the
pre-flight check runs once for the whole sweep, and because a sweep that
found no repositories has no `results` to carry it.

`write_failures` and `autofix_error` record the two failures that
produce no validation error of their own: a rewrite that could not reach
disk, and an auto-fix stage that did not complete. Without them a
consumer reading `results` alone would find nothing to explain a
non-zero `exit_code`.

In this mode the sweep prints neither progress commentary nor the
closing table. Diagnostics go to standard error throughout, so a
redirect captures the document alone:

```bash
gha-workflow-linter lint ~/Repositories --multi-repo --format json \
  > sweep.json
```

### As a Pre-commit Hook

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/modeseven-lfit/gha-workflow-linter
    rev: d86993e21bbcddcfa9dac63cd43213b6a58fa6fb  # frozen: v0.1.1
    hooks:
      - id: gha-workflow-linter
      # Offline; fails the commit on a high or medium stderr merge
      - id: gha-stderr-merge
      # Offline; fails the commit on a Python run that takes in
      # workspace files (PPA001 to PPA008, and PPA011 to PPA013
      # in a composite action)
      - id: gha-python-path
```

### As a GitHub Action

```yaml
name: Check GitHub Actions
on: [push, pull_request]

jobs:
  check-actions:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@f4a75cfd619ee5ce8d5b864b0d183aff3c69b55a
      - name: Check action calls (strict SHA pinning)
        uses: modeseven-lfit/gha-workflow-linter@d86993e21bbcddcfa9dac63cd43213b6a58fa6fb
        with:
          path: .
          fail-on-error: true
          parallel: true
          workers: 4
          require-pinned-sha: true  # Default: require SHA pinning
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  check-actions-allow-tags:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4  # This would fail in strict mode above
      - name: Check action calls (allow tags/branches)
        uses: modeseven-lfit/gha-workflow-linter@d86993e21bbcddcfa9dac63cd43213b6a58fa6fb
        with:
          path: .
          require-pinned-sha: false  # Allow @v4, @main, etc.
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The Action installs its own uv and runs its own Python, so earlier
steps of the job cannot choose either. It fails at once if the job sets
`UV_NO_MODIFY_PATH`: with that variable set, `astral-sh/setup-uv` would
start whichever `uv` comes first on the job's `PATH`.

## Configuration

GHA Workflow Linter is configurable via YAML files, environment variables, or
command-line arguments. Configuration loads in this order:

1. Command-line arguments (highest priority)
2. Environment variables with `GHA_WORKFLOW_LINTER_` prefix
3. Configuration file (lowest priority)

### Configuration File

Create `~/.config/gha-workflow-linter/config.yaml` or use `--config`:

```yaml
# Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
log_level: INFO

# Number of parallel workers (1-32, auto-detected if not specified)
parallel_workers: 4

# File extensions to scan
scan_extensions:
  - ".yml"
  - ".yaml"

# Patterns to exclude from scanning
exclude_patterns:
  - "**/node_modules/**"
  - "**/vendor/**"

# Require actions using commit SHAs (default: true)
require_pinned_sha: true

# Auto-fix broken/invalid references (default: true)
auto_fix: true

# Use latest versions when auto-fixing (default: false)
update_actions: false

# Allow prerelease versions when finding latest versions (default: false)
allow_prerelease: false

# Use two spaces before inline comments when fixing (default: true)
two_space_comments: true

# Skip scanning action.yaml/action.yml files (default: false)
skip_actions: false

# Enable auto-fixing action calls with 'test' in comments (default: false)
fix_test_calls: false

# Git configuration
git:
  timeout_seconds: 30
  use_ssh_agent: true

# Network configuration
network:
  timeout_seconds: 30
  max_retries: 3
  retry_delay_seconds: 1.0
  rate_limit_delay_seconds: 0.1

# Local caching configuration
cache:
  enabled: true
  cache_dir: ~/.cache/gha-workflow-linter
  cache_file: validation_cache.json
  default_ttl_seconds: 604800  # 7 days
  max_cache_size: 10000
  cleanup_on_startup: true
```

### Environment Variables

```bash
export GHA_WORKFLOW_LINTER_LOG_LEVEL=DEBUG
export GHA_WORKFLOW_LINTER_PARALLEL_WORKERS=8
export GHA_WORKFLOW_LINTER_REQUIRE_PINNED_SHA=false
export GHA_WORKFLOW_LINTER_GIT__TIMEOUT_SECONDS=60
export GHA_WORKFLOW_LINTER_CACHE__ENABLED=true
export GHA_WORKFLOW_LINTER_CACHE__DEFAULT_TTL_SECONDS=86400
```

## Local Caching

GHA Workflow Linter includes a local caching system that stores validation
results to improve performance and reduce API calls for later runs.

### Cache Features

- **Automatic Caching**: Validation results are automatically cached locally
- **Version-Based Invalidation**: Tool purges cache when version changes
- **Configurable TTL**: Cache entries expire after seven days by default
- **Size Limits**: Cache size limits prevent excessive disk usage
- **Persistence**: Cache survives between CLI invocations and system restarts
- **Smart Cleanup**: Expired entries are automatically removed

### Cache Commands

```bash
# Show cache information
gha-workflow-linter cache --info

# Remove expired cache entries
gha-workflow-linter cache --cleanup

# Clear all cache entries
gha-workflow-linter cache --purge
```

### Cache Options

```bash
# Bypass cache for a single run
gha-workflow-linter lint --no-cache

# Clear cache and exit
gha-workflow-linter lint --purge-cache

# Override default cache TTL (in seconds)
gha-workflow-linter lint --cache-ttl 3600  # 1 hour
```

### Cache Benefits

- **Performance**: Later runs are faster for validated actions
- **API Efficiency**: Reduces GitHub API calls and respects rate limits better
- **Offline Support**: Validated actions work without network access
- **Bandwidth Savings**: Useful in CI/CD environments with repeated workflows

### Cache Location

By default, cache files go in:

- **Linux/macOS**: `~/.cache/gha-workflow-linter/validation_cache.json`
- **Windows**: `%LOCALAPPDATA%\gha-workflow-linter\validation_cache.json`

You can customize the cache location via configuration file or environment variables.

### Version-Based Cache Invalidation

The cache system automatically detects when you've upgraded to a new version of
the tool and purges all cached entries to ensure consistency. This prevents
issues where validation logic changes between versions could result in stale
cached data.

When the tool detects a version mismatch, you'll see a message like:

```text
INFO Cache version mismatch (cache: 0.1.3, current: 0.1.4). Purging cache.
```

This ensures that:

- Validation logic improvements are always applied
- Bug fixes in validation don't get masked by old cache entries
- New validation features work properly from the first run

**Note**: Caching works for CLI and pre-commit hook usage. GitHub Actions
runners use ephemeral containers, so caching provides no benefit in that
environment.

## Validation Rules

GHA Workflow Linter validates GitHub Actions workflow calls using these rules:

### Action Call Format

Valid action call patterns:

```yaml
# Standard action with version tag
- uses: actions/checkout@v4

# Action with commit SHA
- uses: actions/checkout@8f4d7d2c3f1b2a9d8e5c6a7b4f3e2d1c0b9a8f7e

# Action with branch reference
- uses: actions/checkout@main

# Reusable workflow call
- uses: org/repo/.github/workflows/workflow.yaml@v1.0.0

# With trailing comment
- uses: actions/setup-python@v5.0.0  # Latest stable
```

### Repository Validation

- Organization names: 1-39 characters, alphanumeric and hyphens
- Cannot start/end with hyphen or contain consecutive hyphens
- Repository names: alphanumeric, dots, underscores, hyphens, slashes

### Reference Validation

GHA Workflow Linter validates that references exist using GitHub's GraphQL API:

- **Commit SHAs**: 40-character hexadecimal strings
- **Tags**: Semantic versions (v1.0.0) and other tag formats
- **Branches**: main, master, develop, feature branches

### Supported Reference Types

<!-- markdownlint-disable MD013 -->

<!-- markdownlint-disable MD013 MD060 -->

| Type             | Example                                    | Validation Method  | SHA Pinning                               |
| ---------------- | ------------------------------------------ | ------------------ | ----------------------------------------- |
| Commit SHA       | `f4a75cfd619ee5ce8d5b864b0d183aff3c69b55a` | GitHub GraphQL API | ✅ **Required by default**                |
| Semantic Version | `v1.2.3`, `1.0.0`                          | GitHub GraphQL API | ❌ Fails unless `--no-require-pinned-sha` |
| Branch           | `main`, `develop`                          | GitHub GraphQL API | ❌ Fails unless `--no-require-pinned-sha` |

<!-- markdownlint-enable MD013 MD060 -->

<!-- markdownlint-enable MD013 -->

### SHA Pinning Enforcement

By default, gha-workflow-linter **requires all action calls use commit SHAs** for
security best practices. This helps prevent supply chain attacks and ensures
reproducible builds.

```bash
# Default behavior - fails on non-SHA references
gha-workflow-linter lint  # Fails on @v4, @main, etc.

# Disable SHA pinning policy
gha-workflow-linter lint --no-require-pinned-sha  # Allows @v4, @main, etc.
```

**Security Recommendation**: Keep SHA pinning enabled in production environments
and use automated tools like Dependabot to keep SHA references updated.

## Security Considerations

### SHA Pinning Benefits

- **Supply Chain Security**: Prevents malicious code injection through
compromised action versions
- **Reproducible Builds**: Ensures consistent behavior across builds and environments
- **Immutable References**: SHA references stay fixed, unlike tags and branches
- **Audit Trail**: Clear tracking of exact code versions used in workflows

### Migration Strategy

```bash
# Step 1: Identify unpinned actions
gha-workflow-linter lint --format json | jq '.errors[] | \
  select(.validation_result == "not_pinned_to_sha")'

# Step 2: Temporarily allow unpinned actions during migration
gha-workflow-linter lint --no-require-pinned-sha

# Step 3: Use tools like Dependabot to pin and update SHA references automatically
```

### Dependabot Configuration

Add to `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    commit-message:
      prefix: "ci"
      include: "scope"
```

## Output Formats

### Text Output (Default)

```text
🏷️ gha-workflow-linter version 1.0.0

                                     Scan Summary
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric                ┃ Count ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Workflow files        │    12 │
│ Total action calls    │    45 │
│ Action calls          │    38 │
│ Workflow calls        │     7 │
│ SHA references        │    35 │
│ Tag references        │     8 │
│ Branch references     │     2 │
└───────────────────────┴───────┘

❌ Found 8 validation errors

  - 8 actions not pinned to SHA

Validation Errors:
❌ Invalid action call in workflow: .github/workflows/test.yaml
      - uses: actions/checkout@v4 [not_pinned_to_sha]

❌ Invalid action call in workflow: .github/workflows/test.yaml
      - uses: actions/setup-python@v5 [not_pinned_to_sha]
```

### JSON Output

```bash
gha-workflow-linter lint --format json
```

The tool writes the document to standard output on its own. Log records,
warnings and progress commentary all go to standard error, so a parser
can consume the output directly.

To keep the text report for a reader and still hand a program the
document, name a file with `--json-output`. One run then produces both,
whatever `--format` prints:

```bash
gha-workflow-linter lint --action-calls fix --json-output /tmp/results.json
```

The file receives the same document `--format json` would print, on
every path that prints one once the tool has vetted the path: a normal
run, a scan with nothing to check, a configuration refused after the
configuration loads, and a `--multi-repo` sweep. A refusal before then,
or a refusal of the path itself, still prints its reason under `--format
json` but leaves the file alone. The tool writes it
once, after the run has read everything it examines, and replaces the
file rather than writing into it. The document cannot alter
the run's inputs, and a link named as the output becomes a plain file
instead of carrying the write through to the file it points at. The
write lands in the directory as it resolved when the tool vetted the
path, so retargeting a link above it during the run does not move it.

The file must live outside the linted repository: the repository
enclosing the scanned path, or the scanned path itself when no
repository encloses it, as for a sweep's container. That keeps the
document off workflows, `.git` in every form, and in-tree configuration.
The Git metadata a worktree or submodule keeps elsewhere, named by its
`.git` file, is out of bounds too, for every repository a sweep visits,
as is any `GIT_DIR` or `GIT_COMMON_DIR` the environment sets, with a
relative value resolved from each directory the tool runs Git in, as
Git resolves it.
Anywhere else, the tool also refuses a file the run reads through a
link, such as the target of a symlinked workflow or Dependabot
configuration, a name ending in an
extension the scan reads (`scan_extensions`, and YAML always), a name an
`allow_list.extra_globs` pattern could match, the configuration file
(named by `--config` or discovered by default), the validation cache
and its temporary file, a directory, and a path whose
directory is missing or unwritable. It checks these against the loaded
configuration, before any network call. A run refused before the
configuration loads, such as for `--verbose` with `--quiet`, leaves the
file alone.

These rules protect the repositories the tool lints and the files it
reads itself. They do not extend to configuration other tools read on
its behalf, such as `~/.gitconfig` and the files it includes: that set
belongs to Git, and has no bound. The tool has finished reading by the
time it writes, so naming such a file overwrites it on purpose, as a
shell redirect to it would.

A run that fails before publishing leaves any earlier file in place, so
check the exit status before trusting what the file holds.

Running the tool twice, once per format, does not give the same answer
under `fix` or `update`: the first run repairs the tree, and the second
then reports none of what it repaired.

```json
{
  "rate_limited": false,
  "checks": {
    "action-calls": {"mode": "fix", "ran": true},
    "allow-list": {"mode": "report", "ran": true},
    "stderr-merge": {"mode": "report", "ran": true},
    "python-path": {"mode": "report", "ran": true}
  },
  "error": null,
  "scan_summary": {
    "total_files": 12,
    "total_calls": 45,
    "action_calls": 38,
    "workflow_calls": 7,
    "sha_references": 42,
    "tag_references": 2,
    "branch_references": 1
  },
  "validation_summary": {
    "total_errors": 8,
    "invalid_repositories": 0,
    "invalid_references": 0,
    "invalid_paths": 0,
    "syntax_errors": 0,
    "network_errors": 0,
    "timeouts": 0,
    "not_pinned_to_sha": 8
  },
  "errors": [
    {
      "file_path": ".github/workflows/test.yaml",
      "line_number": 8,
      "raw_line": "      - uses: actions/checkout@v4",
      "organization": "actions",
      "repository": "checkout",
      "reference": "v4",
      "call_type": "action",
      "reference_type": "tag",
      "validation_result": "not_pinned_to_sha",
      "error_message": "Action not pinned to commit SHA"
    }
  ]
}
```

`rate_limited` is always present. It reports whether the GitHub API
throttled the run, in which case the run checked no action call at all,
and `errors` is empty for want of an answer rather than for want of a
problem. Without the key those two documents would look identical.

`checks` is always present, with one entry per check, keyed as the
command-line options name them. Each carries the check's `mode` and
whether it `ran`. The two are not the same question: `mode` is what you
asked for, `ran` is what happened. A throttled run, a run that stopped
after scanning, and an allow-list check that failed and so never ran
all leave the mode untouched while reporting `"ran": false`. An empty
`errors` list from a check that ran means it found nothing; from one
that did not, it means nothing at all. This key separates the two.

`mode` is `null` when the run failed before settling it — refusing an
unsupported mode is itself one such failure. The entries stay present
regardless, sparing a consumer an empty mapping to special-case.

`error` is always present too, and reports why a run could not examine
its input — an unreadable path, say. A run that completed reports `null`.
Note the difference from the `errors` list beside it: `errors` holds
findings *about* the workflows, while `error` says the run never got far
enough to have any. Every path the linter itself reaches emits a
document, so a consumer never has to treat an empty stream as
meaningful.

`stderr_merge` is always present. `checked` says whether the check ran:
`false` separates a check switched off from one that found nothing.
Each finding names its `path`, `line`, `rule`, `confidence`, `detail`,
the source line as `snippet` (`detail` says what uses the output, and
on which line), the captured `variable` where one exists,
the file's `tags`, and whether a directive `suppressed` it. `summary`
counts unsuppressed findings by rule and by confidence, and `problems`
lists files the check could not read:

```json
"stderr_merge": {
  "checked": true,
  "findings": [
    {
      "path": ".github/scripts/gerrit_query.sh",
      "line": 14,
      "rule": "SEM002",
      "confidence": "high",
      "detail": "<how jq reads $json_output, and the line>",
      "snippet": "json_output=$(ssh -p 29418 \"$host\" gerrit query ... 2>&1)",
      "variable": "json_output",
      "tags": [],
      "suppressed": false
    }
  ],
  "summary": {
    "total": 1,
    "suppressed": 0,
    "files_scanned": 9,
    "by_rule": {"SEM001": 0, "SEM002": 1, "SEM003": 0, "SEM004": 0},
    "by_confidence": {"high": 1, "medium": 0, "low": 0}
  },
  "problems": []
}
```

`python_path` is always present too, shaped the same way. Each finding
names its `repo`, `path` (relative to the scanned directory), `line`,
`kind` (`action`, `workflow` or `script`), `rule`, `detail`, the
command as `snippet`, and whether a directive `suppressed` it.
`summary` counts unsuppressed findings by rule and by kind; `enforced`
counts those of `PPA001` to `PPA008`, which `--verify-python-path`
fails on. `verify` says whether the run enforced the check, from the
flag or from `python_path.verify` in the configuration file:

```json
"python_path": {
  "checked": true,
  "verify": false,
  "findings": [
    {
      "repo": "my-action",
      "path": "action.yaml",
      "line": 21,
      "kind": "action",
      "rule": "PPA001",
      "detail": "python -m without -I: the working directory leads sys.path",
      "snippet": "python3 -m json.tool f",
      "suppressed": false
    }
  ],
  "summary": {
    "total": 1,
    "suppressed": 0,
    "enforced": 1,
    "files_scanned": 3,
    "by_rule": {"PPA001": 1, "PPA002": 0, "...": 0, "PPA010": 0},
    "by_kind": {"action": 1, "workflow": 0, "script": 0}
  },
  "problems": []
}
```

Argument parsing sits outside that guarantee, by design. The argument
parser rejects an unreadable path or an out-of-range `--repo-depth`
before the linter starts, exiting `2` — the code reserved for a usage
error, which the linter's own logic never produces. A consumer that sees
`2` knows the invocation was wrong, which is a different question from
anything a document could answer.

## GitHub Action Inputs

Each check takes one mode input, mirroring the command line. The
deprecated inputs still work: the Action translates each into the mode
it asks for and reports a warning naming the input to use instead.
An input left unset passes nothing to the linter, so a configuration
file given with `config-file` still decides it.

<!-- markdownlint-disable MD013 -->

| Input                 | Description                                                   | Required | Default |
| --------------------- | ------------------------------------------------------------- | -------- | ------- |
| `path`                | Path to scan for workflows                                    | No       | `.`     |
| `config-file`         | Path to configuration file                                    | No       |         |
| `log-level`           | Logging level                                                 | No       | `INFO`  |
| `output-format`       | Output format (text, json)                                    | No       | `text`  |
| `fail-on-error`       | Exit with error on failures                                   | No       | `true`  |
| `parallel`            | Enable parallel processing                                    | No       | `true`  |
| `workers`             | Number of parallel workers; auto-detected when unset          | No       |         |
| `exclude`             | Comma-separated exclude patterns                              | No       |         |
| `require-pinned-sha`  | Require actions pinned to commit SHAs                         | No       | `true`  |
| `skip-actions`        | Skip scanning action.yaml/action.yml files                    | No       | `false` |
| `action-calls`        | Action-call check mode: `off`, `report`, `fix` or `update`    | No       |         |
| `verify-action-calls` | Fail on outdated action calls; not effective with `report`    | No       | `false` |
| `auto-fix`            | Deprecated: use `action-calls`                                | No       | `true`  |
| `update-actions`      | Deprecated: use `action-calls: update`                        | No       | `false` |
| `allow-prerelease`    | Allow prerelease versions for latest                          | No       | `false` |
| `two-space-comments`  | Use two spaces before inline comments                         | No       | `true`  |
| `fix-test-calls`      | Fix actions with 'test' in comments                           | No       | `false` |
| `cooldown`            | Days an action release must have been public                  | No       |         |
| `allow-list-cooldown` | Days an allow-list host release must have been public         | No       |         |
| `validation-method`   | Validation method (github-api or git); auto-detected if unset | No       |         |
| `allow-list`          | Allow-list check mode: `off`, `report` or `update`            | No       |         |
| `verify-allow-list`   | Fail when stale allow-list pins remain                        | No       | `false` |
| `update-allow-list`   | Deprecated: use `allow-list: update`                          | No       | `false` |
| `allow-list-org`      | Org for the allow-list `@` shorthand                          | No       |         |
| `stderr-merge`        | Stderr-merge check mode: `off` or `report`                    | No       |         |
| `verify-stderr-merge` | Fail when a high or medium stderr merge remains               | No       | `false` |
| `python-path`         | Python-path check mode: `off` or `report`                     | No       |         |
| `verify-python-path`  | Fail on PPA001 to PPA008, or PPA011 to PPA013 in an action    | No       | `false` |

<!-- markdownlint-enable MD013 -->

## GitHub Action Outputs

<!-- markdownlint-disable MD013 -->

| Output             | Description                          |
| ------------------ | ------------------------------------ |
| `errors-found`     | Number of validation errors          |
| `total-calls`      | Total action calls scanned           |
| `scan-summary`     | JSON summary of results              |
| `allow-list-stale` | Number of stale allow-list pins      |
| `allow-list-fixed` | Number of allow-list pins rewritten  |

<!-- markdownlint-enable MD013 -->

The Action runs the linter once, with `--json-output`, and reads every
output from that run's document, and the outputs describe the run the
log shows, including the findings a fixing mode repaired. With
`output-format: json` the log shows the document itself.

## CLI Options

```text
Usage: gha-workflow-linter lint [OPTIONS] [PATH]

  Scan GitHub Actions workflows for invalid action and workflow calls.

Arguments:
  [PATH]  Path to scan for workflows (default: current directory)

Options:
  -c, --config FILE          Configuration file path
  --github-token TEXT        GitHub API token (auto-detects from GitHub CLI)
  -v, --verbose              Enable verbose output
  -q, --quiet                Suppress all output except errors
  --log-level LEVEL          Set logging level
  -f, --format FORMAT        Output format (text, json)
  --json-output FILE         Also write the JSON document to FILE
  --fail-on-error            Exit with error code if failures found
  --no-fail-on-error         Don't exit with error code
  --parallel                 Enable parallel processing
  --no-parallel              Disable parallel processing
  -j, --workers INTEGER      Number of parallel workers (1-32, auto-detected)
  -e, --exclude PATTERN      Patterns to exclude (multiples accepted)
  --require-pinned-sha       Require actions pinned to commit SHAs (default)
  --no-require-pinned-sha    Allow actions with tags/branches
  --action-calls MODE        off|report|fix|update (default: fix)
  --verify-action-calls      Fail when an action call has fallen behind
  --allow-list MODE          off|report|update (default: report)
  --verify-allow-list        Fail when an allow-list pin is stale
  --allow-list-cooldown INTEGER
                             Days an allow-list host release must be public
                             before a pin is stale against it (default: 0)
  --stderr-merge MODE        off|report (default: report)
  --verify-stderr-merge      Fail when a high or medium stderr merge remains
  --stderr-merge-min-confidence LEVEL
                             Lowest confidence --verify-stderr-merge fails
                             on: low, medium or high (default: medium)
  --python-path MODE         off|report (default: report)
  --verify-python-path       Fail when a Python run takes in workspace files
  --show-suppressed          List findings silenced by a directive
  --allow-prerelease         Allow prerelease versions for latest
  --no-allow-prerelease      Disallow prerelease versions
  --two-space-comments       Use two spaces before inline comments
  --no-two-space-comments    Use single space before inline comments
  --skip-actions             Skip scanning action.yaml/action.yml files
  --no-skip-actions          Scan action.yaml/action.yml files (default)
  --fix-test-calls           Fix actions with 'test' in comments
  --cooldown INTEGER         Days an action release must be public before
                             updating (defaults to the Dependabot cooldown
                             setting, then 0)
  --version                  Show version and exit
  --help                     Show this message and exit

Note: Most boolean options use config file defaults when not specified.
      CLI flags override config file settings.
```

## Integration Examples

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Check Actions') {
            steps {
                sh 'pip install gha-workflow-linter'
                sh 'gha-workflow-linter lint --format json > results.json'
                archiveArtifacts artifacts: 'results.json'
            }
        }
    }
}
```

### Docker Usage

```bash
# Using published image
docker run --rm -v "$(pwd):/workspace" \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  ghcr.io/modeseven-lfit/gha-workflow-linter:latest lint /workspace

# Build local image
docker build -t gha-workflow-linter .
docker run --rm -v "$(pwd):/workspace" \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  gha-workflow-linter lint /workspace
```

The build context excludes `.git`, so a local image reports version
`0.0.0`. To stamp a real version, pass it as a build argument:

```bash
docker build --build-arg VERSION=1.2.3 -t gha-workflow-linter .
```

## Error Types

<!-- markdownlint-disable MD013 -->

| Error Type           | Description                                              | Resolution                                                              |
| -------------------- | -------------------------------------------------------- | ----------------------------------------------------------------------- |
| `invalid_repository` | Repository not found                                     | Check org/repo name spelling                                            |
| `invalid_reference`  | Branch/tag/SHA not found                                 | Verify reference exists                                                 |
| `invalid_path`       | Subdirectory action path not found at the referenced ref | Check the subdirectory path (e.g. `owner/repo/path`) exists at that ref |
| `invalid_syntax`     | Malformed action call                                    | Fix YAML syntax                                                         |
| `network_error`      | Connection failed                                        | Check network/credentials                                               |
| `timeout`            | Validation timed out                                     | Increase timeout settings                                               |
| `not_pinned_to_sha`  | Action not using SHA                                     | Pin to commit SHA or use `--no-require-pinned-sha`                      |

<!-- markdownlint-enable MD013 -->

## Development

### Setup Development Environment

```bash
git clone https://github.com/modeseven-lfit/gha-workflow-linter.git
cd gha-workflow-linter
uv sync --extra dev
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=gha_workflow_linter

# Run specific test categories
uv run pytest -m unit
uv run pytest -m integration
uv run pytest -m "not slow"
```

### Code Quality

```bash
# Format code
uv run ruff format .

# Lint code
uv run ruff check .

# Type checking
uv run mypy src/gha_workflow_linter

# Pre-commit hooks
uv run prek run --all-files
```

### Building and Publishing

**Local Builds:**

```bash
uv build
```

This project uses automated CI/CD workflows for building and publishing:

**Development/Testing:**

- Pull requests trigger the `build-test.yaml` workflow
- Automatically runs tests, audits, linting
- Validates the package builds without errors

**Releases:**

- The `build-test-release.yaml` workflow performs publishing/releasing
- Triggered by pushing a git tag to the repository
- Automatically builds, tests and publishes the package

## Architecture

GHA Workflow Linter follows a modular architecture with clear separation of
concerns:

- **CLI Interface**: Typer-based command-line interface
- **Configuration**: Pydantic models with YAML/env support
- **Scanner**: Workflow file discovery and parsing
- **Patterns**: Regex-based action call extraction
- **Validator**: Git-based remote validation
- **Models**: Type-safe data structures

## Performance

GHA Workflow Linter performance optimizations:

- **Parallel Processing**: Multi-threaded validation
- **Caching**: Repository and reference validation caching
- **Rate Limiting**: Configurable delays to respect API limits
- **Efficient API Operations**: Uses GitHub GraphQL API

Typical performance on a repository with 50 workflows and 200 action calls:

- **Serial**: ~60 seconds
- **Parallel (4 workers)**: ~15 seconds
- **Cached**: ~2 seconds (follow-up runs)

## Security Notes

- **Token Security**: Tokens are never logged or stored permanently
- **Environment Variables**: Recommended method for token management
- **Private Repositories**: Requires appropriate token permissions
- **Rate Limiting**: Proactive management prevents API abuse
- **API Efficiency**: Batch queries reduce API surface area

### Pre-commit Hook

The repository includes a pre-commit hook that runs gha-workflow-linter
on its own workflows:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/modeseven-lfit/gha-workflow-linter
    rev: d86993e21bbcddcfa9dac63cd43213b6a58fa6fb  # frozen: v0.1.1
    hooks:
      - id: gha-workflow-linter
```

### Development Setup

For contributors, use the development setup script. It needs
[uv](https://docs.astral.sh/uv/getting-started/installation/) on your
`PATH` and exits with an error if `uv` is missing:

```bash
# Install development environment with self-linting
./scripts/setup-dev.sh

# This sets up:
# - A .venv with the development dependencies (uv sync --extra dev)
# - Git hooks through prek (including gha-workflow-linter)
# - GitHub authentication (GitHub CLI recommended)
# - Self-linting test
```

## Troubleshooting

### Authentication Issues

**GitHub CLI not found:**

```text
❌ Unable to get GitHub token from any source
💡 Authentication options:
   • Install GitHub CLI: https://cli.github.com/
   • Or set environment variable: export GITHUB_TOKEN=ghp_xxx
   • Or use --github-token flag with your personal access token
```

**GitHub CLI not authenticated:**

```bash
# Check authentication status
gh auth status

# Login if not authenticated
gh auth login
```

**Token permissions:**

- Ensure your token has `public_repo` scope for public repositories
- Use `repo` scope for private repositories
- Check token validity: `gh auth token` should return a valid token

**Rate limiting:**

- Without authentication: 60 requests/hour
- With GitHub token: 5,000 requests/hour
- Large repositories may require authentication to avoid limits

## Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run the test suite and linting (including self-linting)
5. Submit a pull request

## License

Licensed under the Apache License 2.0. See the LICENSE file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/modeseven-lfit/gha-workflow-linter/issues)
- **Discussions**: [GitHub Discussions](https://github.com/modeseven-lfit/gha-workflow-linter/discussions)
- **Documentation**: [Read the Docs](https://gha-workflow-linter.readthedocs.io)

## Acknowledgments

Built with modern Python tooling:

- [Typer](https://typer.tiangolo.com/) for CLI interface
- [Pydantic](https://docs.pydantic.dev/) for data validation
- [Rich](https://rich.readthedocs.io/) for beautiful terminal output
- [uv](https://docs.astral.sh/uv/) for dependency management
- [pytest](https://pytest.org/) for testing
