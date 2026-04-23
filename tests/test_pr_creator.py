"""
tests/test_pr_creator.py

Unit tests for PRCreator — all GitHub API calls mocked.
No live repo or token required.
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from github import GithubException

from pipeline.github.pr_creator import (
    PRCreator,
    PRResult,
    _slugify,
    _rule_filename,
    _branch_name,
    _format_evidence,
    _build_pr_body,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_RULE = """\
title: PowerShell Encoded Command Execution
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects PowerShell executing encoded commands
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
tags:
    - attack.execution
    - attack.t1059.001
"""

SAMPLE_EVENTS = [
    {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -enc JABjAG0AZA==",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
    },
    {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -EncodedCommand JABjAG0AZA==",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
    },
]


@pytest.fixture
def mock_validation_result():
    result = MagicMock()
    result.passed = True
    result.lint_passed = True
    result.attack_passed = True
    result.noise_passed = True
    result.fp_rate = 0.005
    result.feedback = None
    return result


@pytest.fixture
def mock_repo():
    """Minimal mock of a PyGithub Repository object."""
    repo = MagicMock()

    # Default branch
    repo.default_branch = "main"

    # HEAD SHA
    branch_mock = MagicMock()
    branch_mock.commit.sha = "abc123def456"
    repo.get_branch.return_value = branch_mock

    # Owner
    owner_mock = MagicMock()
    owner_mock.login = "testowner"
    type(repo).owner = PropertyMock(return_value=owner_mock)

    # No existing file (404 on get_contents)
    repo.get_contents.side_effect = GithubException(404, "Not Found", None)

    # create_file returns something
    repo.create_file.return_value = (MagicMock(), MagicMock())

    # No open PRs by default
    repo.get_pulls.return_value = iter([])

    # Created PR
    pr_mock = MagicMock()
    pr_mock.html_url = "https://github.com/testowner/testrepo/pull/42"
    pr_mock.number = 42
    repo.create_pull.return_value = pr_mock

    return repo


@pytest.fixture
def pr_creator(mock_repo):
    """PRCreator with mocked GitHub client."""
    with patch("pipeline.github.pr_creator.Github") as mock_gh_cls:
        mock_gh = MagicMock()
        mock_gh.get_repo.return_value = mock_repo
        mock_gh_cls.return_value = mock_gh

        with patch.dict("os.environ", {
            "GITHUB_TOKEN": "fake-token",
            "GITHUB_REPO": "testowner/testrepo",
        }):
            creator = PRCreator()
            creator._repo = mock_repo
            return creator


# ---------------------------------------------------------------------------
# Utility function tests
# ---------------------------------------------------------------------------

class TestSlugify:
    def test_basic(self):
        assert _slugify(
            "PowerShell Encoded Command") == "powershell-encoded-command"

    def test_special_characters(self):
        assert _slugify(
            "T1059.001 / Sub-technique!") == "t1059-001-sub-technique"

    def test_truncation(self):
        long = "a" * 60
        result = _slugify(long, max_len=40)
        assert len(result) <= 40

    def test_empty(self):
        result = _slugify("")
        assert result == ""

    def test_no_trailing_dash(self):
        result = _slugify("hello---", max_len=10)
        assert not result.endswith("-")


class TestRuleFilename:
    def test_extracts_title_from_yaml(self):
        filename = _rule_filename("T1059.001", SAMPLE_RULE)
        assert filename.startswith("T1059.001-")
        assert filename.endswith(".yml")
        assert "powershell" in filename

    def test_fallback_when_no_title(self):
        filename = _rule_filename(
            "T1059.001", "detection:\n  condition: selection\n")
        assert filename.startswith("T1059.001-")
        assert filename.endswith(".yml")

    def test_max_length(self):
        long_title = "title: " + "A very long rule title " * 5
        filename = _rule_filename("T1059.001", long_title)
        # stem should be capped — total filename reasonable
        assert len(filename) < 100


class TestBranchName:
    def test_format(self):
        branch = _branch_name("T1059.001", SAMPLE_RULE)
        assert branch.startswith("rule/T1059.001-")

    def test_no_spaces(self):
        branch = _branch_name("T1059.001", SAMPLE_RULE)
        assert " " not in branch


class TestFormatEvidence:
    def test_empty_events(self):
        result = _format_evidence([])
        assert "No missed events" in result

    def test_channel_excluded(self):
        result = _format_evidence(SAMPLE_EVENTS)
        assert "Microsoft-Windows-Sysmon" not in result

    def test_caps_at_five(self):
        events = [{"Image": f"proc_{i}.exe"} for i in range(10)]
        result = _format_evidence(events)
        assert "5 more events" in result

    def test_shows_populated_fields(self):
        result = _format_evidence(SAMPLE_EVENTS[:1])
        assert "powershell.exe" in result
        assert "-enc" in result


# ---------------------------------------------------------------------------
# PRCreator tests
# ---------------------------------------------------------------------------

class TestPRCreator:

    def test_create_pr_returns_result(self, pr_creator, mock_validation_result):
        result = pr_creator.create_pr(
            technique_id="T1059.001",
            technique_name="PowerShell",
            rule_yaml=SAMPLE_RULE,
            missed_events=SAMPLE_EVENTS,
            validation_result=mock_validation_result,
        )

        assert isinstance(result, PRResult)
        assert result.pr_number == 42
        assert result.pr_url == "https://github.com/testowner/testrepo/pull/42"
        assert result.branch_name.startswith("rule/T1059.001-")
        assert result.rule_filename.endswith(".yml")

    def test_creates_branch_from_head(self, pr_creator, mock_repo, mock_validation_result):
        pr_creator.create_pr(
            technique_id="T1059.001",
            technique_name="PowerShell",
            rule_yaml=SAMPLE_RULE,
            missed_events=SAMPLE_EVENTS,
            validation_result=mock_validation_result,
        )

        mock_repo.create_git_ref.assert_called_once()
        call_kwargs = mock_repo.create_git_ref.call_args
        assert call_kwargs[1]["sha"] == "abc123def456"
        assert call_kwargs[1]["ref"].startswith("refs/heads/rule/")

    def test_commits_rule_to_rules_dir(self, pr_creator, mock_repo, mock_validation_result):
        pr_creator.create_pr(
            technique_id="T1059.001",
            technique_name="PowerShell",
            rule_yaml=SAMPLE_RULE,
            missed_events=SAMPLE_EVENTS,
            validation_result=mock_validation_result,
        )

        mock_repo.create_file.assert_called_once()
        call_kwargs = mock_repo.create_file.call_args
        assert call_kwargs[1]["path"].startswith("rules/")
        assert call_kwargs[1]["path"].endswith(".yml")
        assert call_kwargs[1]["content"] == SAMPLE_RULE

    def test_opens_pr_with_correct_title(self, pr_creator, mock_repo, mock_validation_result):
        pr_creator.create_pr(
            technique_id="T1059.001",
            technique_name="PowerShell",
            rule_yaml=SAMPLE_RULE,
            missed_events=SAMPLE_EVENTS,
            validation_result=mock_validation_result,
        )

        mock_repo.create_pull.assert_called_once()
        call_kwargs = mock_repo.create_pull.call_args
        assert "T1059.001" in call_kwargs[1]["title"]
        assert "PowerShell" in call_kwargs[1]["title"]

    def test_pr_body_contains_evidence(self, pr_creator, mock_repo, mock_validation_result):
        pr_creator.create_pr(
            technique_id="T1059.001",
            technique_name="PowerShell",
            rule_yaml=SAMPLE_RULE,
            missed_events=SAMPLE_EVENTS,
            validation_result=mock_validation_result,
        )

        body = mock_repo.create_pull.call_args[1]["body"]
        assert "T1059.001" in body
        assert "powershell.exe" in body.lower()

    def test_pr_body_contains_fp_rate(self, pr_creator, mock_repo, mock_validation_result):
        mock_validation_result.fp_rate = 0.005

        pr_creator.create_pr(
            technique_id="T1059.001",
            technique_name="PowerShell",
            rule_yaml=SAMPLE_RULE,
            missed_events=SAMPLE_EVENTS,
            validation_result=mock_validation_result,
        )

        body = mock_repo.create_pull.call_args[1]["body"]
        assert "0.5%" in body

    def test_existing_branch_does_not_raise(self, pr_creator, mock_repo, mock_validation_result):
        """Branch already exists — should reuse it without raising."""
        mock_repo.create_git_ref.side_effect = GithubException(
            422, "Reference already exists", None)

        # Should not raise
        result = pr_creator.create_pr(
            technique_id="T1059.001",
            technique_name="PowerShell",
            rule_yaml=SAMPLE_RULE,
            missed_events=SAMPLE_EVENTS,
            validation_result=mock_validation_result,
        )
        assert result.pr_number == 42

    def test_existing_pr_updates_body_not_duplicate(
        self, pr_creator, mock_repo, mock_validation_result
    ):
        """If a PR is already open for the branch, update it instead of creating a new one."""
        existing_pr = MagicMock()
        existing_pr.number = 42
        existing_pr.html_url = "https://github.com/testowner/testrepo/pull/42"
        mock_repo.get_pulls.return_value = iter([existing_pr])

        pr_creator.create_pr(
            technique_id="T1059.001",
            technique_name="PowerShell",
            rule_yaml=SAMPLE_RULE,
            missed_events=SAMPLE_EVENTS,
            validation_result=mock_validation_result,
        )

        mock_repo.create_pull.assert_not_called()
        existing_pr.edit.assert_called_once()

    def test_update_file_when_already_exists(self, pr_creator, mock_repo, mock_validation_result):
        """If rule file already exists on branch, update rather than create."""
        existing_file = MagicMock()
        existing_file.sha = "existingsha123"
        mock_repo.get_contents.side_effect = None
        mock_repo.get_contents.return_value = existing_file

        pr_creator.create_pr(
            technique_id="T1059.001",
            technique_name="PowerShell",
            rule_yaml=SAMPLE_RULE,
            missed_events=SAMPLE_EVENTS,
            validation_result=mock_validation_result,
        )

        mock_repo.update_file.assert_called_once()
        mock_repo.create_file.assert_not_called()

    def test_missing_token_raises(self):
        with patch.dict("os.environ", {"GITHUB_TOKEN": "", "GITHUB_REPO": "owner/repo"}):
            with pytest.raises(EnvironmentError, match="GITHUB_TOKEN"):
                PRCreator()

    def test_missing_repo_raises(self):
        with patch.dict("os.environ", {"GITHUB_TOKEN": "fake", "GITHUB_REPO": ""}):
            with pytest.raises(EnvironmentError, match="GITHUB_REPO"):
                PRCreator()
