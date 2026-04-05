"""
engine.py — SQLite-backed Sigma detection engine
=================================================
Path: closed-loop-adversarial-detection/pipeline/detection/engine.py

Responsibilities
----------------
- Load Sigma rules from a directory of YAML files
- Convert each rule to SQL via pySigma sqlite backend
  (sysmon_pipeline + windows_logsource_pipeline)
- Register a REGEXP Python UDF on the sqlite3 connection
- Load LogEvent JSONL into an in-memory sqlite3 table
- Execute each rule's SQL query, return structured RuleMatchResult objects

Design notes
------------
- Pipeline is constructed fresh per rule to prevent state contamination
  between conversions (pySigma pipeline objects are stateful)
- All columns are created as TEXT; sqlite3 numeric coercion handles
  gt/gte/lt/lte comparisons transparently
- Column names use backtick quoting throughout to match pySigma output
- Missing fields (sparse Phase 1 logs) surface as sqlite3.OperationalError
  at execution time — caught and labelled "execution_error: <field>" so
  result_parser.py can distinguish "no match" from "field not present"
- REGEXP UDF uses re.IGNORECASE by default — Windows path/field values are
  case-insensitive and Sigma |re patterns don't consistently include (?i)
- One bad rule file never aborts the batch — each rule is isolated
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sigma.backends.sqlite import sqlite as sqlite_module
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline

logger = logging.getLogger(__name__)

# Table name used in all generated SQL — must match backend.table
_TABLE = "logs"


# ---------------------------------------------------------------------------
# REGEXP UDF
# ---------------------------------------------------------------------------

def _regexp_udf(pattern: str, value: Optional[str]) -> int:
    """
    SQLite REGEXP function.

    Returns 1 (match) or 0 (no match).  sqlite3 expects an int return, not bool.
    IGNORECASE applied globally — Windows field values are case-insensitive and
    Sigma |re patterns vary in whether they include (?i).  If a rule explicitly
    embeds (?-i) we honour it since re.search respects inline flags.
    """
    if value is None:
        return 0
    try:
        return 1 if re.search(pattern, str(value), re.IGNORECASE) else 0
    except re.error as exc:
        logger.debug("REGEXP UDF: invalid pattern %r — %s", pattern, exc)
        return 0


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class RuleMatchResult:
    """
    Output unit from the detection engine — one per rule file processed.

    fired          : True if at least one event matched
    matched_events : list of raw event dicts that triggered the match
    skipped        : True if the rule could not be converted or executed
    skip_reason    : one of:
                       "parse_error: ..."
                       "unsupported_modifier: ..."
                       "conversion_error: ..."
                       "no_query_generated"
                       "execution_error: ..."
                       "unexpected_error: ..."
    sql_query      : the generated SQL (None if conversion failed)
    """
    rule_id: str
    rule_title: str
    rule_path: str
    fired: bool
    matched_events: list[dict] = field(default_factory=list)
    skipped: bool = False
    skip_reason: Optional[str] = None
    sql_query: Optional[str] = None


# ---------------------------------------------------------------------------
# JSONL loader
# ---------------------------------------------------------------------------

def load_events_from_jsonl(path: Path) -> list[dict]:
    """
    Load log events from a JSONL file (one JSON object per line).
    Skips blank lines and logs a warning for malformed lines rather than
    raising — a single bad line shouldn't abort the corpus load.
    """
    events: list[dict] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    logger.warning("%s line %d: expected JSON object, got %s — skipped",
                                   path, lineno, type(obj).__name__)
                    continue
                events.append(obj)
            except json.JSONDecodeError as exc:
                logger.warning(
                    "%s line %d: JSON parse error — %s", path, lineno, exc)
    logger.debug("Loaded %d events from %s", len(events), path)
    return events


# ---------------------------------------------------------------------------
# In-memory DB construction
# ---------------------------------------------------------------------------

def _infer_columns(events: list[dict]) -> list[str]:
    """Union of all keys across all events — the table schema is the superset."""
    cols: set[str] = set()
    for e in events:
        cols.update(e.keys())
    return sorted(cols)


def _build_db(events: list[dict]) -> sqlite3.Connection:
    """
    Create an in-memory sqlite3 DB, register REGEXP UDF, load all events.

    Column names are backtick-quoted to match pySigma's generated SQL.
    All values are stored as TEXT; sqlite3 type affinity handles numeric ops.
    Missing fields for any given event are stored as NULL.
    """
    if not events:
        raise ValueError("Cannot build detection DB — event list is empty.")

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.create_function("REGEXP", 2, _regexp_udf)

    columns = _infer_columns(events)
    col_defs = ", ".join(f"`{c}` TEXT" for c in columns)
    conn.execute(f"CREATE TABLE {_TABLE} ({col_defs})")

    col_list = ", ".join(f"`{c}`" for c in columns)
    placeholders = ", ".join("?" for _ in columns)
    insert_sql = f"INSERT INTO {_TABLE} ({col_list}) VALUES ({placeholders})"

    rows = [tuple(str(e[c]) if e.get(c) is not None else None for c in columns)
            for e in events]
    conn.executemany(insert_sql, rows)
    conn.commit()

    logger.debug("DB ready: %d events, %d columns", len(events), len(columns))
    return conn


# ---------------------------------------------------------------------------
# Rule conversion (fresh pipeline per rule)
# ---------------------------------------------------------------------------

def _convert_rule_to_sql(rule_collection: SigmaCollection) -> tuple[Optional[str], Optional[str]]:
    """
    Convert a SigmaCollection (single rule) to a SQL SELECT query.

    Returns (sql, None) on success or (None, reason_string) on failure.

    Pipeline is constructed fresh each call — pySigma pipeline objects
    accumulate state across conversions and reuse causes silent field-mapping
    errors on the second+ rule.
    """
    pipeline = sysmon_pipeline() + windows_logsource_pipeline()
    backend = sqlite_module.sqliteBackend(pipeline)
    backend.table = _TABLE

    try:
        queries = backend.convert(rule_collection)
    except NotImplementedError as exc:
        # Unsupported modifier (e.g. something the sqlite backend can't handle)
        return None, f"unsupported_modifier: {exc}"
    except SigmaError as exc:
        return None, f"conversion_error: {exc}"
    except Exception as exc:  # noqa: BLE001
        return None, f"conversion_error: {type(exc).__name__}: {exc}"

    if not queries:
        return None, "no_query_generated"

    # backend.convert returns a list; single rule → single query
    return queries[0], None


# ---------------------------------------------------------------------------
# Core engine class
# ---------------------------------------------------------------------------

class DetectionEngine:
    """
    SQLite-backed Sigma detection engine.

    Parameters
    ----------
    rules_dir     : directory to glob for .yml rule files
    events        : pre-loaded list of log event dicts
    glob_pattern  : glob pattern for rule files (default: **/*.yml)

    Usage
    -----
        events = load_events_from_jsonl(Path("corpus/attack/proc_create.jsonl"))
        engine = DetectionEngine(
            rules_dir=Path("rules/"),
            events=events,
        )
        results = engine.run()
    """

    def __init__(
        self,
        rules_dir: Path,
        events: list[dict],
        *,
        glob_pattern: str = "**/*.yml",
    ) -> None:
        self.rules_dir = Path(rules_dir)
        self.events = events
        self.glob_pattern = glob_pattern

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> list[RuleMatchResult]:
        """
        Load all rules from rules_dir, execute against the loaded events,
        return one RuleMatchResult per rule file found.
        """
        rule_paths = sorted(self.rules_dir.glob(self.glob_pattern))
        if not rule_paths:
            logger.warning("No rule files found in %s (pattern: %s)",
                           self.rules_dir, self.glob_pattern)
            return []

        conn = _build_db(self.events)
        results: list[RuleMatchResult] = []

        for path in rule_paths:
            result = self._process_rule(path, conn)
            results.append(result)

        fired_count = sum(1 for r in results if r.fired)
        skipped_count = sum(1 for r in results if r.skipped)
        logger.info(
            "Run complete — %d rules | %d fired | %d skipped | %d no-match",
            len(results), fired_count, skipped_count,
            len(results) - fired_count - skipped_count,
        )
        return results

    def run_on_events(self, events: list[dict]) -> list[RuleMatchResult]:
        """
        Swap the event corpus and re-run all rules.
        Useful for back-to-back attack vs benign corpus runs without
        re-instantiating the engine.
        """
        self.events = events
        return self.run()

    # ------------------------------------------------------------------
    # Internal: per-rule pipeline
    # ------------------------------------------------------------------

    def _process_rule(self, path: Path, conn: sqlite3.Connection) -> RuleMatchResult:
        """Parse → convert → execute a single rule file. Never raises."""

        # --- 1. Parse ---------------------------------------------------
        # Catch Exception broadly — SigmaCollection.load_ruleset can raise
        # SigmaError for invalid Sigma structure, yaml.scanner.ScannerError
        # for malformed YAML, or other exceptions for edge cases.
        # None of these should abort the batch.
        try:
            rule_collection = SigmaCollection.load_ruleset([path])
        except Exception as exc:  # noqa: BLE001
            logger.warning("Parse error in %s: %s", path, exc)
            return RuleMatchResult(
                rule_id=path.stem,
                rule_title=path.stem,
                rule_path=str(path),
                fired=False,
                skipped=True,
                skip_reason=f"parse_error: {type(exc).__name__}: {exc}",
            )

        # Extract metadata (id + title) from the parsed rule object
        rule_id, rule_title = path.stem, path.stem
        if rule_collection.rules:
            r = rule_collection.rules[0]
            rule_id = str(r.id) if r.id else path.stem
            rule_title = str(r.title) if r.title else path.stem

        # --- 2. Convert -------------------------------------------------
        sql, err = _convert_rule_to_sql(rule_collection)
        if err:
            logger.warning(
                "Conversion skipped [%s] '%s': %s", rule_id, rule_title, err)
            return RuleMatchResult(
                rule_id=rule_id,
                rule_title=rule_title,
                rule_path=str(path),
                fired=False,
                skipped=True,
                skip_reason=err,
            )

        # --- 3. Execute -------------------------------------------------
        return self._execute(rule_id, rule_title, str(path), sql, conn)

    def _execute(
        self,
        rule_id: str,
        rule_title: str,
        rule_path: str,
        sql: str,
        conn: sqlite3.Connection,
    ) -> RuleMatchResult:
        """Run the SQL query; handle missing-column errors gracefully."""
        try:
            cursor = conn.execute(sql)
            rows = [dict(row) for row in cursor.fetchall()]
            fired = bool(rows)

            if fired:
                logger.info("FIRED  [%s] '%s' — %d match(es)",
                            rule_id, rule_title, len(rows))
            else:
                logger.debug("MISS   [%s] '%s'", rule_id, rule_title)

            return RuleMatchResult(
                rule_id=rule_id,
                rule_title=rule_title,
                rule_path=rule_path,
                fired=fired,
                matched_events=rows,
                sql_query=sql,
            )

        except sqlite3.OperationalError as exc:
            # Most common cause: a field in the WHERE clause doesn't exist in
            # the table (sparse Phase 1 log schema — e.g. ParentCommandLine).
            # This is expected — label it clearly for result_parser.py.
            err_msg = f"execution_error: {exc}"
            logger.warning("Execution error [%s] '%s': %s | SQL: %s",
                           rule_id, rule_title, exc, sql)
            return RuleMatchResult(
                rule_id=rule_id,
                rule_title=rule_title,
                rule_path=rule_path,
                fired=False,
                skipped=True,
                skip_reason=err_msg,
                sql_query=sql,
            )

        except Exception as exc:  # noqa: BLE001
            err_msg = f"unexpected_error: {type(exc).__name__}: {exc}"
            logger.error("Unexpected error [%s] '%s': %s", rule_id, rule_title, exc,
                         exc_info=True)
            return RuleMatchResult(
                rule_id=rule_id,
                rule_title=rule_title,
                rule_path=rule_path,
                fired=False,
                skipped=True,
                skip_reason=err_msg,
                sql_query=sql,
            )


# ---------------------------------------------------------------------------
# CLI smoke test
# Usage: python engine.py <rules_dir> <events.jsonl>
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(levelname)-8s %(name)s — %(message)s",
    )

    if len(sys.argv) < 3:
        print("Usage: python engine.py <rules_dir> <events.jsonl>")
        sys.exit(1)

    _rules_dir = Path(sys.argv[1])
    _events_path = Path(sys.argv[2])

    _events = load_events_from_jsonl(_events_path)
    _engine = DetectionEngine(rules_dir=_rules_dir, events=_events)
    _results = _engine.run()

    _fired = [r for r in _results if r.fired]
    _skipped = [r for r in _results if r.skipped]
    _missed = [r for r in _results if not r.fired and not r.skipped]

    print(f"\n{'=' * 60}")
    print(f"  Total : {len(_results)}")
    print(f"  Fired : {len(_fired)}")
    print(f"  Missed: {len(_missed)}")
    print(f"  Skipped: {len(_skipped)}")
    print(f"{'=' * 60}")

    for r in _fired:
        print(
            f"  FIRED   [{r.rule_id[:8]}] {r.rule_title} — {len(r.matched_events)} event(s)")
    for r in _skipped:
        print(f"  SKIPPED [{r.rule_id[:8]}] {r.rule_title} — {r.skip_reason}")
    for r in _missed:
        print(f"  MISS    [{r.rule_id[:8]}] {r.rule_title}")
