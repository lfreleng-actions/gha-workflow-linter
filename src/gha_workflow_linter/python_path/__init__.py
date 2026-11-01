# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Detection of Python and uv calls that import from the workspace.

The engine in ``_engine`` is the reference scanner, kept internal until
the linter exposes it as a check.
"""
