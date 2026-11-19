#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

ORACLE="$SRC/build/oracle-bin"
[ -x "$ORACLE/kat" ] || { echo "missing $ORACLE/kat — mayhem/build.sh did not build the oracle" >&2; emit_ctrf "flint-oracle" 0 1 0; exit 1; }

passed=0
failed=0
skipped=0

# 1. Known answers worked out by hand (n_remove, fmpz_remove, the string parsers, fmpz_poly_remove):
#    every expected line must appear verbatim in the probe's output.
EXPECTED='KAT n_remove 5 7
KAT n_remove_big 1 28778071877862015
KAT n_remove2 63 1
KAT fmpz_remove 100 10935
KAT fmpz_set_str16 -255
KAT fmpz_set_str62 3843
KAT fmpz_get_str36 byw97um9s91dlz68tsi
KAT fmpz_set_str_bad -1
KAT fmpz_poly_remove 3 3  1 1 1
KAT fmpz_poly_set_str 9
KAT fmpz_poly_set_str_bad -1
KAT fmpq_poly_set_str 3  1/2 0 -3/4
KAT fmpq_set_str -3/4
KAT fmpz_mpoly_set_str_pretty 0 3 x^2*y+3*y-1
KAT arb_set_str 0 0 0.3750000000'
ACTUAL=$("$ORACLE/kat" 2>&1)
while IFS= read -r line; do
  if printf '%s\n' "$ACTUAL" | grep -qxF -- "$line"; then
    passed=$((passed + 1))
  else
    echo "FAIL expected: $line" >&2
    failed=$((failed + 1))
  fi
done <<< "$EXPECTED"
[ "$(printf '%s\n' "$ACTUAL" | grep -c '^KAT ')" -eq "$(printf '%s\n' "$EXPECTED" | wc -l)" ] \
  || { echo "FAIL: unexpected number of KAT lines" >&2; failed=$((failed + 1)); }

# 2. Upstream's whole unit-test suite: every module's test main (build/oracle/build/<module>/test/main,
#    built by `make tests` in build.sh), run with no arguments, which runs every test in it
#    (TEST_MAIN, src/test_helpers.h). Each test prints "<name> ... <seconds> (PASS)" (or FAIL /
#    SKIPPED); those lines are the CTRF counts. A main that dies (a failing test calls flint_abort,
#    a FLINT_ASSERT fires) counts one more failure, and so does one that exits 0 without printing a
#    single PASS. FLINT_TEST_MULTIPLIER scales the number of random iterations per test (upstream's
#    own knob, default 1); 0.1 keeps the whole suite to a few minutes on the image's cores.
export FLINT_TEST_MULTIPLIER="${FLINT_TEST_MULTIPLIER:-0.1}"
export LD_LIBRARY_PATH="$SRC/build/oracle${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
MAINS=$(find "$SRC/build/oracle/build" -path '*/test/main' -type f -perm -u+x | sort)
NMAINS=$(printf '%s\n' "$MAINS" | grep -c . || true)
if [ "$NMAINS" -lt 100 ]; then
  echo "FAIL: only $NMAINS upstream test mains under build/oracle/build — mayhem/build.sh did not run 'make tests'" >&2
  failed=$((failed + 1))
else
  LOGDIR=$(mktemp -d "${TMPDIR:-/tmp}/flint-tests.XXXXXX")
  printf '%s\n' "$MAINS" | xargs -P "$MAYHEM_JOBS" -I{} sh -c '
      m=${1#"$3"/}; m=${m%/main}; m=${m%/test}; m=${m:-test}
      "$1" > "$2/$m.log" 2>&1; echo $? > "$2/$m.rc"' _ {} "$LOGDIR" "$SRC/build/oracle/build"
  for rcf in "$LOGDIR"/*.rc; do
    m=$(basename "$rcf" .rc)
    out=$(sed 's/\x1b\[[0-9;]*m//g' "$LOGDIR/$m.log")
    p=$(printf '%s\n' "$out" | grep -c '(PASS)$' || true)
    f=$(printf '%s\n' "$out" | grep -c '(FAIL)$' || true)
    k=$(printf '%s\n' "$out" | grep -c '(SKIPPED)$' || true)
    rc=$(cat "$rcf")
    passed=$((passed + p)); failed=$((failed + f)); skipped=$((skipped + k))
    if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then
      echo "FAIL upstream $m: exit $rc after $p passed: $(printf '%s' "$out" | tail -3)" >&2
      failed=$((failed + 1))
    elif [ "$rc" -eq 0 ] && [ "$p" -eq 0 ] && [ "$k" -eq 0 ]; then
      echo "FAIL upstream $m: exited 0 without running a test" >&2
      failed=$((failed + 1))
    elif [ "$f" -ne 0 ]; then
      echo "FAIL upstream $m: $(printf '%s\n' "$out" | grep -A3 '(FAIL)$' | head -8)" >&2
    fi
  done
  echo "upstream suite: $NMAINS test mains, multiplier $FLINT_TEST_MULTIPLIER"
  rm -rf "$LOGDIR"
fi

# 3. Upstream's Python suite (CI's `make check PYTHON=1`, Makefile.in: python3 src/python/flint_ctypes.py
#    against the shared libflint.so in build/oracle, already on LD_LIBRARY_PATH above). The script runs
#    its test_* functions, printing "test_<name>...PASS" after each (a failing assert raises and stops
#    it), then doctest.testmod(FAIL_FAST) over every docstring example and sys.exit(<failures>) on any
#    failure. Each PASS line is one result; the doctest is one more, passed iff the script exits 0 and
#    prints its closing rule. A non-zero exit, or fewer PASS lines than the file defines test_
#    functions, is a failure. Many of these tests build values from strings through gr_set_str.
PYSUITE="$SRC/src/python/flint_ctypes.py"
if ! command -v python3 >/dev/null 2>&1 || [ ! -f "$PYSUITE" ]; then
  echo "FAIL: python3 or $PYSUITE missing — cannot run upstream's Python suite" >&2
  failed=$((failed + 1))
else
  NPYTESTS=$(grep -c '^def test_[a-z0-9_]*(' "$PYSUITE" || true)
  PYOUT=$(cd "${TMPDIR:-/tmp}" && python3 "$PYSUITE" 2>&1); PYRC=$?
  pyp=$(printf '%s\n' "$PYOUT" | grep -cE '^test_[a-z0-9_]+\.\.\.PASS' || true)
  passed=$((passed + pyp))
  if [ "$PYRC" -ne 0 ] || [ "$NPYTESTS" -lt 1 ] || [ "$pyp" -lt "$NPYTESTS" ]; then
    echo "FAIL upstream python: exit $PYRC, $pyp/$NPYTESTS test_ functions passed: $(printf '%s\n' "$PYOUT" | tail -15)" >&2
    failed=$((failed + 1))
  elif [ "$(printf '%s\n' "$PYOUT" | tail -1)" = "----------------------------------------------------------" ]; then
    passed=$((passed + 1))
  else
    echo "FAIL upstream python: doctest did not finish: $(printf '%s\n' "$PYOUT" | tail -5)" >&2
    failed=$((failed + 1))
  fi
  echo "upstream python suite: $pyp/$NPYTESTS test_ functions + doctest, exit $PYRC"
fi

emit_ctrf "flint-oracle" "$passed" "$failed" "$skipped"
