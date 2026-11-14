#!/usr/bin/env bash
# clone-demo.sh UMASK COMMIT DIR LOG [fix]
# A scratch clone of the Warden-task3 repo at COMMIT, made and tested with
# UMASK. Tools and the module cache are symlinks to the main checkout's, as
# in the worktree. With "fix", after a failed make test it runs the chmod the
# preflight printed and runs make test once more.
set -u
mask=$1 commit=$2 dir=$3 log=$4 fix=${5:-}
umask "$mask"
main=$HOME/Desktop/Warden
{
  echo "# scratch clone $dir of ~/Desktop/Warden-task3 at $commit, umask $(umask) for git clone and make"
  echo "# $(date -Iseconds), load $(cut -d' ' -f1-3 /proc/loadavg)"
  git clone -q --no-checkout ~/Desktop/Warden-task3 "$dir" && git -C "$dir" checkout -q --detach "$commit" || exit 1
  # Same tool links as the worktree; the directories git and these mkdirs make get the umask.
  mkdir -p "$dir/.tools" "$dir/.cache"
  for t in go kyverno py vector; do ln -s "$main/.tools/$t" "$dir/.tools/$t"; done
  ln -s "$main/.cache/go-mod" "$dir/.cache/go-mod"
  echo "# head $(git -C "$dir" rev-parse HEAD)"
  echo "# git status --short:"
  git -C "$dir" status --short | sed 's/^/#   /'; echo "#   (end)"
  echo "# modes:"
  stat -c '#   %A %U %n' "$dir" "$dir/.cache" "$dir/.tools" "$(dirname "$dir")"
  echo "# \$ make test"
  cd "$dir" || exit 1
  taskset -c 0-7,16-31 make test 2>&1; rc=$?
  echo "# make test exit: $rc"
  if [[ $rc -ne 0 && $fix == fix ]]; then
    cmd=$(grep -m1 '^  chmod go-w ' "$log" | sed 's/^  //')
    echo "# \$ $cmd   (the fix the preflight printed)"
    $cmd
    stat -c '#   %A %U %n' "$dir" "$dir/.cache" "$dir/.cache/test-tmp"
    echo "# \$ make test   (still umask $(umask))"
    taskset -c 0-7,16-31 make test 2>&1; rc=$?
    echo "# make test exit: $rc"
  fi
  echo "# end $(date -Iseconds)"
} >"$log" 2>&1
