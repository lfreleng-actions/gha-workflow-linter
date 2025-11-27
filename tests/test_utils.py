# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for utility functions."""

from __future__ import annotations

from gha_workflow_linter.models import ActionCall, ActionCallType, ReferenceType
from gha_workflow_linter.utils import has_test_comment


class TestHasTestComment:
    """Test has_test_comment utility function."""

    def test_has_test_comment_with_test_lowercase(self) -> None:
        """Test detection of 'test' in comment."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # test",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# test",
        )
        assert has_test_comment(action_call) is True

    def test_has_test_comment_with_test_uppercase(self) -> None:
        """Test detection of 'TEST' in comment."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # TEST",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# TEST",
        )
        assert has_test_comment(action_call) is True

    def test_has_test_comment_with_test_capitalized(self) -> None:
        """Test detection of 'Test' in comment."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # Test",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# Test",
        )
        assert has_test_comment(action_call) is True

    def test_has_test_comment_with_testing(self) -> None:
        """Test detection of 'testing' in comment."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # testing",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# testing",
        )
        assert has_test_comment(action_call) is True

    def test_has_test_comment_with_testing_capitalized(self) -> None:
        """Test detection of 'Testing' in comment."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # Testing",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# Testing",
        )
        assert has_test_comment(action_call) is True

    def test_has_test_comment_with_tested(self) -> None:
        """Test detection of 'tested' in comment."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # tested version",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# tested version",
        )
        assert has_test_comment(action_call) is True

    def test_has_test_comment_in_middle_of_sentence(self) -> None:
        """Test detection of 'test' in middle of comment."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # This is a test comment",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# This is a test comment",
        )
        assert has_test_comment(action_call) is True

    def test_has_test_comment_at_end_of_sentence(self) -> None:
        """Test detection of 'test' at end of comment."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # For test",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# For test",
        )
        assert has_test_comment(action_call) is True

    def test_has_test_comment_no_space_after_hash(self) -> None:
        """Test detection when no space after hash."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  #test",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="#test",
        )
        assert has_test_comment(action_call) is True

    def test_has_test_comment_returns_false_for_latest(self) -> None:
        """Test that 'latest' does not match (contains 'test' but not at word boundary)."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # latest",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# latest",
        )
        assert has_test_comment(action_call) is False

    def test_has_test_comment_returns_false_for_greatest(self) -> None:
        """Test that 'greatest' does not match."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # greatest",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# greatest",
        )
        assert has_test_comment(action_call) is False

    def test_has_test_comment_returns_false_for_contest(self) -> None:
        """Test that 'contest' does not match."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # contest",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# contest",
        )
        assert has_test_comment(action_call) is False

    def test_has_test_comment_returns_false_for_protest(self) -> None:
        """Test that 'protest' does not match."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # protest",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# protest",
        )
        assert has_test_comment(action_call) is False

    def test_has_test_comment_returns_false_for_v4(self) -> None:
        """Test that version comments don't match."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # v4",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# v4",
        )
        assert has_test_comment(action_call) is False

    def test_has_test_comment_returns_false_for_stable(self) -> None:
        """Test that 'stable' doesn't match."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # stable",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# stable",
        )
        assert has_test_comment(action_call) is False

    def test_has_test_comment_returns_false_for_production(self) -> None:
        """Test that 'production' doesn't match."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # Production ready",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# Production ready",
        )
        assert has_test_comment(action_call) is False

    def test_has_test_comment_returns_false_for_empty_comment(self) -> None:
        """Test that empty comment returns False."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="",
        )
        assert has_test_comment(action_call) is False

    def test_has_test_comment_returns_false_for_none_comment(self) -> None:
        """Test that None comment returns False (using default from model)."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
        )
        assert has_test_comment(action_call) is False

    def test_has_test_comment_with_multiple_words_including_test(self) -> None:
        """Test with multiple words where one is 'test'."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # This test is important",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# This test is important",
        )
        assert has_test_comment(action_call) is True

    def test_has_test_comment_case_insensitive_mixed(self) -> None:
        """Test case insensitivity with mixed case."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # TeSt",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# TeSt",
        )
        assert has_test_comment(action_call) is True

    def test_has_test_comment_with_punctuation(self) -> None:
        """Test with punctuation around test."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # (test)",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# (test)",
        )
        assert has_test_comment(action_call) is True

    def test_has_test_comment_with_hyphen(self) -> None:
        """Test with hyphenated test word."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # test-version",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# test-version",
        )
        assert has_test_comment(action_call) is True

    def test_has_test_comment_returns_false_for_attestation(self) -> None:
        """Test that 'attestation' does not match (test in middle of word)."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # attestation",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# attestation",
        )
        assert has_test_comment(action_call) is False
