#!/usr/bin/env bash
set -Eeuo pipefail

# 兼容旧入口：CRC32/WXSHADOW 验证现在必须在合并 mkpm.kpm 上运行。
# 完整入口在兼容性 demo 目录，支持 status/probe/hide/redirect/crc32/all：
#   examples/rustfrida-compat-app/run_demo_spawn.sh

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "$ROOT/examples/rustfrida-compat-app/run_demo_spawn.sh" 10 "$@"
