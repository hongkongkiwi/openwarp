#!/usr/bin/env bash
# Manage OpenWarp worktrees. Every worktree lives under .worktrees/ inside the
# repository, which is gitignored; worktrees outside that directory are not used.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
wt_root="$root/.worktrees"
repo="$(basename "$root")"
cd "$root"

die() {
  echo "worktree: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
usage: scripts/worktree.sh <command>

  new <name> [branch] [base]   create .worktrees/<name>; branch defaults to
                               <name>, base to main. An existing branch is
                               attached instead of created.
  list                         list every registered worktree
  move <path> [name]           relocate an existing registered worktree into
                               .worktrees/; name defaults to the directory
                               name without the "<repo>-" prefix
  remove <name> [--force]      remove a clean worktree, prune stale entries
  prune                        prune metadata for deleted worktrees
EOF
  exit 2
}

case "${1:-}" in
  new)
    name="${2:-}"
    [ -n "$name" ] || usage
    case "$name" in
      */*|.|..) die "name must be one path component" ;;
    esac
    branch="${3:-$name}"
    base="${4:-main}"
    path="$wt_root/$name"

    [ -e "$path" ] && die "$path already exists"
    git check-ignore -q "$path" || die ".worktrees/ is not gitignored; fix .gitignore first"
    mkdir -p "$wt_root"

    if git show-ref --verify --quiet "refs/heads/$branch"; then
      git worktree add "$path" "$branch"
    else
      git worktree add "$path" -b "$branch" "$base"
    fi
    echo "worktree ready: $path (branch $branch)"
    ;;

  list)
    git worktree list
    ;;

  move)
    src="${2:-}"
    [ -n "$src" ] || usage
    [ -d "$src" ] || die "$src does not exist"
    src="$(cd "$src" && git rev-parse --show-toplevel)"
    [ "$src" = "$root" ] && die "refusing to move the main checkout"
    case "$src" in
      "$wt_root"/*) die "$src is already inside $wt_root" ;;
    esac
    git worktree list --porcelain | grep -Fxq "worktree $src" || die "$src is not a registered worktree"

    base="$(basename "$src")"
    name="${3:-${base#"$repo"-}}"
    case "$name" in
      */*|.|..) die "name must be one path component" ;;
    esac
    dst="$wt_root/$name"
    [ -e "$dst" ] && die "$dst already exists"
    git check-ignore -q "$dst" || die ".worktrees/ is not gitignored; fix .gitignore first"
    mkdir -p "$wt_root"

    git worktree move "$src" "$dst"
    echo "moved: $src -> $dst"
    ;;

  remove)
    name="${2:-}"
    [ -n "$name" ] || usage
    path="$wt_root/$name"
    [ -d "$path" ] || die "$path is not a worktree"
    case "$path" in
      "$wt_root"/*) ;;
      *) die "$path is outside $wt_root" ;;
    esac

    if [ -n "$(git -C "$path" status --porcelain)" ]; then
      [ "${3:-}" = "--force" ] || die "$name has uncommitted changes; verify they are junk or merged before --force"
      git worktree remove --force "$path"
    else
      git worktree remove "$path"
    fi
    git worktree prune
    echo "removed: $path"
    ;;

  prune)
    git worktree prune -v
    ;;

  *)
    usage
    ;;
esac
