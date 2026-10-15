#!/bin/sh
# Print the GitHub release notes for TAG: the commit subjects since the previous
# tag (the repo commits straight to main, so GitHub's PR-based notes are empty).
# Used by the release job in .github/workflows/ci.yml; needs the full git history.
set -eu
tag=${1:?usage: release-notes.sh TAG}
repo=${GITHUB_REPOSITORY:-mrpriv4te/pwndbg-imgui}

if prev=$(git describe --tags --abbrev=0 --match 'v*' "$tag^" 2>/dev/null); then
    range="$prev..$tag"
else
    range="$tag"  # first release: the whole history
    prev=""
fi

echo "## Changes"
echo
git log --no-merges --format='- %s (%h)' "$range"
echo
echo "## Install"
echo
echo '```bash'
echo "pipx install git+https://github.com/$repo@$tag"
echo '```'
if [ -n "$prev" ]; then
    echo
    echo "**Full changelog:** https://github.com/$repo/compare/$prev...$tag"
fi
