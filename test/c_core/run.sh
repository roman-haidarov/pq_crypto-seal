#!/usr/bin/env bash
# Builds ext/pq_crypto_seal/pqs_core.c and the vendored AEGIS-256 sources
# without Ruby and runs test/c_core/core_test.c.
#
# Usage, from the repository root:
#   test/c_core/run.sh                          # address + undefined (+ leak)
#   PQC_SEAL_SANITIZE=leak test/c_core/run.sh
#   PQC_SEAL_SANITIZE=memory test/c_core/run.sh # clang only
#   PQC_SEAL_SANITIZE=thread test/c_core/run.sh
#   PQC_SEAL_SANITIZE=none test/c_core/run.sh

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"
EXT="${ROOT}/ext/pq_crypto_seal"
AEGIS="${EXT}/vendor/libaegis/src"
CC="${CC:-cc}"
MODE="${PQC_SEAL_SANITIZE:-address}"

case "${MODE}" in
  address) SAN=(-fsanitize=address,undefined -fno-sanitize-recover=all) ;;
  leak) SAN=(-fsanitize=leak) ;;
  memory) SAN=(-fsanitize=memory -fsanitize-memory-track-origins=2) ;;
  thread) SAN=(-fsanitize=thread) ;;
  none) SAN=() ;;
  *)
    echo "unknown PQC_SEAL_SANITIZE=${MODE} (address|leak|memory|thread|none)" >&2
    exit 2
    ;;
esac

SSL_CFLAGS=()
SSL_LIBS=(-lcrypto)
if [ -n "${OPENSSL_ROOT_DIR:-}" ]; then
  SSL_CFLAGS=(-I"${OPENSSL_ROOT_DIR}/include")
  SSL_LIBS=(-L"${OPENSSL_ROOT_DIR}/lib" -Wl,-rpath,"${OPENSSL_ROOT_DIR}/lib" -lcrypto)
elif command -v pkg-config >/dev/null 2>&1 && pkg-config --exists openssl; then
  read -r -a SSL_CFLAGS <<< "$(pkg-config --cflags openssl)"
  read -r -a SSL_LIBS <<< "$(pkg-config --libs openssl)"
fi

COMMON=(-std=c11 -g -O1 -fno-omit-frame-pointer -pthread "${SAN[@]}")
STRICT=(-Wall -Wextra -Wpedantic -Werror)

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

vendor_objects=()
for source in "${AEGIS}"/aegis256/*.c "${AEGIS}"/common/*.c; do
  object="${workdir}/$(basename "${source}" .c).o"
  "${CC}" "${COMMON[@]}" -w -I"${AEGIS}/include" -c "${source}" -o "${object}"
  vendor_objects+=("${object}")
done

"${CC}" "${COMMON[@]}" "${STRICT[@]}" "${SSL_CFLAGS[@]}" -I"${AEGIS}/include" -I"${EXT}" -isystem "${AEGIS}" \
  "${HERE}/core_test.c" "${EXT}/pqs_core.c" "${EXT}/aegis_unused_stubs.c" \
  "${vendor_objects[@]}" "${SSL_LIBS[@]}" -o "${workdir}/core_test"

export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:halt_on_error=1:abort_on_error=1:strict_string_checks=1:detect_stack_use_after_return=1}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}"
export TSAN_OPTIONS="${TSAN_OPTIONS:-halt_on_error=1:second_deadlock_stack=1}"
export MSAN_OPTIONS="${MSAN_OPTIONS:-halt_on_error=1}"
export LSAN_OPTIONS="${LSAN_OPTIONS:-exitcode=23}"

"${workdir}/core_test"
echo "c core tests (${MODE}): ok"
