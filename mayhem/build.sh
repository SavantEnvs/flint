#!/usr/bin/env bash
#
# mayhem/build.sh — builds, inside the commit image (as `mayhem`, in /mayhem):
#   1. libflint (static) with $SANITIZER_FLAGS + $DEBUG_FLAGS      -> build/san
#   2. one libFuzzer binary + one -standalone reproducer per harness -> /mayhem/<target>
#   3. libflint with NORMAL flags plus all of upstream's unit tests (build/oracle) and the
#      known-answer probe mayhem/oracle/kat.c, which mayhem/test.sh runs  -> build/oracle-bin
# Everything generated lives in the gitignored build/ (and /mayhem/oracle), so the build is
# re-runnable offline: it needs only clang, autotools, make and the apt -dev packages GMP/MPFR.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"
OUT=/mayhem
OUT_ORACLE=build/oracle-bin

# FLINT's gr layer calls through function pointers of a different (ABI-compatible) type
# (`function`), and its small-integer / exponent-vector code shifts by the full word width or
# into the sign bit where the result is not used (`shift`). Those are benign on every target
# FLINT supports and fire on the first inputs of most harnesses, hiding everything behind them,
# so just these two UBSan checks are off; ASan and the rest of UBSan stay halting.
RELAX="-fno-sanitize=function,shift"

[ -x configure ] || ./bootstrap.sh

# --build/--host are pinned so configure does not bake -march=<this CPU> into the flags: the
# image is built on one machine and run on others. Assembly is off for the same reason.
configure_in() {
    local dir="$1"; shift
    local stamp="$*"
    mkdir -p "$dir"
    if [ ! -f "$dir/Makefile" ] || [ "$(cat "$dir/.stamp" 2>/dev/null)" != "$stamp" ]; then
        [ ! -f "$dir/Makefile" ] || make -C "$dir" clean >/dev/null 2>&1 || true
        (cd "$dir" && "$SRC/configure" --build=x86_64-linux-gnu --host=x86_64-linux-gnu \
            --disable-shared --enable-static --disable-assembly CC="$CC" "$@")
        printf '%s' "$stamp" > "$dir/.stamp"
    fi
}

# ---- 1. sanitized library --------------------------------------------------------------------
FUZZ_CFLAGS="-O1 -ffunction-sections -fdata-sections $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
# --enable-assert defines FLINT_WANT_ASSERT, so FLINT_ASSERT() checks the library's internal
# invariants and documented preconditions (upstream CI builds and tests with it); without it they
# compile to nothing and a broken invariant goes on silently.
configure_in build/san --enable-assert "CFLAGS=$FUZZ_CFLAGS"
make -C build/san -j"$MAYHEM_JOBS" library build/include
SAN=build/san
INC="-I$SAN/build/include"
LIBS="-Wl,--gc-sections $SAN/libflint.a -lgmp -lmpfr -lm -lpthread"

# ---- 2. harnesses ----------------------------------------------------------------------------
$CXX $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build/lsan_off.o
for h in mayhem/harnesses/fuzz_*.c; do
    t=$(basename "$h" .c)
    $CC $FUZZ_CFLAGS $LIB_FUZZING_ENGINE $INC "$h" build/lsan_off.o $LIBS -o "$OUT/$t"
    $CC $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS $INC "$STANDALONE_FUZZ_MAIN" "$h" build/lsan_off.o $LIBS \
        -o "$OUT/$t-standalone"
done

# ---- 3. oracle: normal flags, no sanitizers --------------------------------------------------
# Upstream's whole unit-test suite (`make tests`: one self-contained static build/<module>/test/main
# per module), configured like upstream CI (--enable-assert) and, like upstream's default, as a
# shared library: linked statically, each of the ~135 mains would carry its own 64 MB copy of
# libflint (8.6 GB). The mains find build/oracle/libflint.so through their rpath.
# test.sh runs every one of them in place, with no arguments, i.e. every test of every module.
# Plus a known-answer probe.
configure_in build/oracle --enable-shared --disable-static --enable-assert "CFLAGS=-O1 $COVERAGE_FLAGS"
make -C build/oracle -j"$MAYHEM_JOBS" library build/include
make -C build/oracle -j"$MAYHEM_JOBS" tests
mkdir -p "$OUT_ORACLE"
$CC -O1 $COVERAGE_FLAGS -Ibuild/oracle/build/include mayhem/oracle/kat.c \
    -Lbuild/oracle -Wl,-rpath,"$SRC/build/oracle" -lflint -lgmp -lmpfr -lm -lpthread -o "$OUT_ORACLE/kat"
