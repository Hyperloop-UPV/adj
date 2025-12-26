#!/usr/bin/env bash
set -euo pipefail

SOURCE_BRANCH="test-adj"
COMMIT_HASH="171924c"

if [[ -z "${COMMIT_HASH:-}" ]]; then
  echo "Usage: $0 <commit-hash>"
  exit 1
fi

# Safety checks
current_branch=$(git branch --show-current)
if [[ "$current_branch" != "$SOURCE_BRANCH" ]]; then
  echo "ERROR: Run this script from branch '$SOURCE_BRANCH'"
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "ERROR: Working tree is not clean"
  exit 1
fi

# Get all local branches except source
branches=$(git for-each-ref --format='%(refname:short)' refs/heads/ | grep -v "^${SOURCE_BRANCH}$")

for branch in $branches; do
  echo "----------------------------------------"
  echo "Cherry-picking into branch: $branch"
  git checkout "$branch"

  if git cherry-pick "$COMMIT_HASH"; then
    echo "✔ Cherry-pick successful in $branch"
  else
    echo "✖ Conflict in $branch"
    echo "Resolve conflicts, then run:"
    echo "  git cherry-pick --continue"
    echo "or abort with:"
    echo "  git cherry-pick --abort"
    exit 1
  fi
done

git checkout "$SOURCE_BRANCH"
echo "----------------------------------------"
echo "Cherry-pick completed on all branches."
