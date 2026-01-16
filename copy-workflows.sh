#!/usr/bin/env bash
set +e 

SOURCE_BRANCH="test-adj"
COMMIT_HASH="103678c"


# Safety checks
current_branch=$(git branch --show-current)
if [[ "$current_branch" != "$SOURCE_BRANCH" ]]; then
  echo "ERROR: Run this script from branch '$SOURCE_BRANCH'"
  exit 1
fi

# if [[ -n "$(git status --porcelain)" ]]; then
#   echo "ERROR: Working tree is not clean"
#   exit 1
# fi

# Get all local branches except source
branches=$(git branch -r| grep -v "^${SOURCE_BRANCH}$" | grep -v "origin/HEAD" | grep -v "test-adj"| sed 's|^ *origin/||')

for branch in $branches; do

git checkout "$branch" > /dev/null  2> /dev/null ;
git cherry-pick  -n "$COMMIT_HASH" > /dev/null  2> /dev/null ;

git add .github;


git commit -m "chore(adj-validator): copy ADJ-Validator from $SOURCE_BRANCH" > /dev/null ;

echo "Cherry Pick from branch: $branch"

done

