# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Python import-path scan: where Python or uv runs workspace files."""

# The YAML reader moved to the shared shell package; the name stays
# reachable here for callers that import it from this package.
from gha_workflow_linter.shell import _yaml as _yaml
