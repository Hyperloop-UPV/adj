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

  git cherry-pick "$COMMIT_HASH";
  git cherry_pick --continue;
  git add .github; 
  git commit -m "Copy workflows from $SOURCE_BRANCH"
  git push origin "$branch"

  fi
done

git checkout "$SOURCE_BRANCH"
echo "----------------------------------------"
echo "Cherry-pick completed on all branches."
