#!/usr/bin/env bash
set -euo pipefail

# --- Settings ---
APP_NAME="sniffer"            # базовое имя бинарника
ENTRYPOINT="./cmd/sniffer"    # путь к main пакету
DIST="dist"
LDFLAGS_EXTRA="-s -w"         # можно добавить свои флаги

VERSION_FILE="VERSION"

# --- Helpers ---
die() { echo "Error: $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

build_target() {
  local os="$1" arch="$2" version="$3" ext=""
  [[ "$os" == "windows" ]] && ext=".exe"
  local out="${DIST}/${APP_NAME}_v${version}_${os}_${arch}${ext}"

  echo "→ build ${os}/${arch} -> ${out}"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=1 \
    go build -trimpath -ldflags "${LDFLAGS_EXTRA} -X main.version=${version}" \
    -o "$out" "$ENTRYPOINT"
}

# --- Checks ---
need_cmd git
need_cmd go
[[ -f "$VERSION_FILE" ]] || echo "0.0.0" > "$VERSION_FILE"

current_version="$(cat "$VERSION_FILE")"

# Отделяем суффикс, если есть (например 1.2.3-rc1)
suffix=""
base_version="$current_version"
if [[ "$current_version" == *-* ]]; then
  suffix="-${current_version#*-}"
  base_version="${current_version%%-*}"
fi

IFS='.' read -r major minor patch <<< "$base_version"

bump_type="${1:-}"
if [[ -z "$bump_type" ]]; then
  echo "Usage: $0 [major|minor|patch|set-suffix] [suffix]"
  exit 1
fi

# --- Make sure we’re in a git repo ---
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "not a git repository"

# Автокоммитим незакоммиченное перед релизом, чтобы ничего не потерять
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "🧹 Staging current changes..."
  git add -A
  git commit -m "chore: pre-release housekeeping"
fi

# --- Compute new version ---
if [[ "$bump_type" == "set-suffix" ]]; then
  new_suffix="${2:-}"
  [[ -n "$new_suffix" ]] || die "Usage: $0 set-suffix <suffix>"
  new_version="${major}.${minor}.${patch}-${new_suffix}"
else
  case "$bump_type" in
    major) major=$((major + 1)); minor=0; patch=0 ;;
    minor) minor=$((minor + 1)); patch=0 ;;
    patch) patch=$((patch + 1)) ;;
    *) die "Invalid bump type: $bump_type (use major|minor|patch|set-suffix)" ;;
  esac
  new_version="${major}.${minor}.${patch}${suffix}"
fi

# Не перетирать существующий тег случайно
if git rev-parse -q --verify "refs/tags/v${new_version}" >/dev/null; then
  die "tag v${new_version} already exists"
fi

echo "$new_version" > "$VERSION_FILE"
echo "Version bumped to ${new_version}"

git add "$VERSION_FILE"
git commit -m "chore: bump version to v${new_version}"
git tag -a "v${new_version}" -m "Release v${new_version}"
git push origin HEAD --tags

# --- Build artifacts ---
mkdir -p "$DIST"

build_target darwin  amd64 "$new_version"
build_target darwin  arm64 "$new_version"
build_target windows amd64 "$new_version"

# (опционально) архивирование — раскомментируй, если нужно
# pushd "$DIST" >/dev/null
#   for f in ${APP_NAME}_v${new_version}_*; do
#     zip -q "${f}.zip" "$f"
#   done
# popd >/dev/null

# --- Commit artifacts ---
git add "${DIST}/"
git commit -m "build: release binaries for v${new_version}" || true
git push

echo
echo "✅ Done."
echo "   Version: v${new_version}"
echo "   Artifacts:"
ls -1 "${DIST}/" | sed 's/^/   - /'
