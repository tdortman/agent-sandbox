#!/usr/bin/env bash
#
# Materialize patched dependency sources into vendor/.
#
# vendor/ is generated, not committed. Each entry names its source, either a
# crates.io archive or a git checkout at a pinned revision, and the patch
# applied to it. The dev shell runs this script on entry (downloading archives
# and fetching git); the Nix derivation runs it with the sources it already
# fetched.
#
# Usage: materialize-vendor.sh [--force] [<source>...]
#
#   --force    re-materialize even when the stamp matches
#   <source>   .crate archives, matched to entries by file name, plus at most
#              one directory used as the git checkout root for git entries.
#              When any source is given, every entry needs one. Archive
#              sha256 values below are still verified.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

# crate <name> <version> <sha256(.crate)> <patch>
# git   <name> <version> <subdir> <url> <rev> <patch>
entries=(
  "crate rustls 0.23.43 0283386ce02abc0151e1761d08802dfe86c173b0b494af5cbc086574e453da06 patches/rustls-0.23.43.patch"
  "crate quinn 0.11.11 0c1a41e437b6bbd489372cd4971de128e85c855f56c57f283d20ff016cf7c0a8 patches/quinn-0.11.11.patch"
  "crate quinn-proto 0.11.16 2f4bfc015262b9df63c8845072ce59068853ff5872180c2ce2f13038b970e560 patches/quinn-proto-0.11.16.patch"
  "git h3 0.0.8 h3 https://github.com/hyperium/h3.git c38a1af632afbbbc8f6716c196ad67f40bc122e3 patches/h3-0.0.8.patch"
  "git h3-datagram 0.0.2 h3-datagram https://github.com/hyperium/h3.git c38a1af632afbbbc8f6716c196ad67f40bc122e3 patches/h3-datagram-0.0.2.patch"
  "git h3-webtransport 0.1.2 h3-webtransport https://github.com/hyperium/h3.git c38a1af632afbbbc8f6716c196ad67f40bc122e3 patches/h3-webtransport-0.1.2.patch"
)

force=0
archives=()
git_root=
for arg in "$@"; do
  case "$arg" in
    --force) force=1 ;;
    -*) echo "materialize-vendor: unknown option $arg" >&2; exit 2 ;;
    *) if [ -d "$arg" ]; then git_root=$arg; else archives+=("$arg"); fi ;;
  esac
done

# Print the provided archive for one crate, or nothing when none matches.
archive_for() {
  local want="$1-$2.crate" archive base
  for archive in "${archives[@]}"; do
    base=$(basename "$archive")
    case "$base" in
      # A plain file name, or a Nix store path ("<hash>-<name>").
      "$want" | *"-$want")
        printf '%s' "$archive"
        return
        ;;
    esac
  done
}

# Print a checkout of the pinned revision, cloning it into target/ if needed.
checkout_for() {
  local url="$1" rev="$2" repo
  if [ -n "$git_root" ]; then
    printf '%s' "$git_root"
    return
  fi
  repo="target/vendor-git/$(basename "$url" .git)"
  if [ ! -d "$repo/.git" ] ||
    [ "$(git -C "$repo" rev-parse HEAD 2>/dev/null || true)" != "$rev" ]; then
    echo "materialize-vendor: fetching $url at $rev" >&2
    rm -rf "$repo"
    mkdir -p "$repo"
    git -C "$repo" init -q
    git -C "$repo" remote add origin "$url"
    git -C "$repo" fetch -q --depth 1 origin "$rev"
    git -C "$repo" checkout -q FETCH_HEAD
  fi
  printf '%s' "$repo"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

mkdir -p vendor/.stamps

for entry in "${entries[@]}"; do
  kind=${entry%% *}
  rest=${entry#* }

  if [ "$kind" = "crate" ]; then
    read -r name version sha256 patch_file <<<"$rest"
    target="vendor/$name-$version"
    want=$(sha256sum "$patch_file" | cut -d' ' -f1)
  else
    read -r name version subdir url rev patch_file <<<"$rest"
    target="vendor/$name"
    want="git-$rev-$(sha256sum "$patch_file" | cut -d' ' -f1)"
  fi
  stamp="vendor/.stamps/$(basename "$target")"

  if [ "$force" -eq 0 ] && [ -f "$target/Cargo.toml" ] &&
    [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$want" ]; then
    continue
  fi

  if [ "$kind" = "crate" ]; then
    archive=$(archive_for "$name" "$version")
    if [ "${#archives[@]}" -gt 0 ] && [ -z "$archive" ]; then
      echo "materialize-vendor: no archive provided for $name-$version" >&2
      exit 2
    fi
    if [ -z "$archive" ]; then
      archive="$tmpdir/$name-$version.crate"
      echo "materialize-vendor: downloading $name-$version"
      curl -sSfL "https://static.crates.io/crates/$name/$name-$version.crate" -o "$archive"
    fi

    actual=$(sha256sum "$archive" | cut -d' ' -f1)
    if [ "$actual" != "$sha256" ]; then
      echo "materialize-vendor: sha256 mismatch for $name-$version" >&2
      echo "  expected $sha256" >&2
      echo "  actual   $actual" >&2
      exit 1
    fi

    rm -rf "$target"
    mkdir -p "$target"
    tar -xzf "$archive" -C "$target" --strip-components=1
  else
    if [ -z "$git_root" ] && [ "${#archives[@]}" -gt 0 ]; then
      echo "materialize-vendor: no git checkout provided for $name" >&2
      exit 2
    fi
    repo=$(checkout_for "$url" "$rev")
    if [ ! -d "$repo/$subdir" ]; then
      echo "materialize-vendor: $url has no $subdir directory" >&2
      exit 2
    fi
    rm -rf "$target"
    cp -a "$repo/$subdir" "$target"
  fi

  chmod -R u+w "$target"
  patch -p1 --fuzz=0 -d "$target" < "$patch_file"
  printf '%s\n' "$want" > "$stamp"
  echo "materialize-vendor: materialized $target"
done
