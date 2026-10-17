#!/bin/sh
# Print the GitHub release notes for TAG. With docs/releases/TAG.md (hand-written:
# summary, one section per feature with screenshots from docs/releases/TAG/), that
# text comes first, its relative image links pointing at the files as of REF (the tag
# by default; RELEASE_REF=<commit> for a release whose images were added after it).
# Then the install line and the commit subjects since the previous tag (the repo
# commits straight to main, so GitHub's PR-based notes are empty). Used by the release
# job in .github/workflows/ci.yml; needs the full git history.
set -eu
tag=${1:?usage: release-notes.sh TAG}
repo=${GITHUB_REPOSITORY:-mrpriv4te/pwndbg-imgui}
ref=${RELEASE_REF:-$tag}
notes="docs/releases/$tag.md"

if prev=$(git describe --tags --abbrev=0 --match 'v*' "$tag^" 2>/dev/null); then
    range="$prev..$tag"
else
    range="$tag"  # first release: the whole history
    prev=""
fi

if [ -f "$notes" ]; then
    raw="https://raw.githubusercontent.com/$repo/$ref/docs/releases/$tag/"
    sed -e "s#](\./$tag/#]($raw#g" -e "s#](${tag}/#]($raw#g" \
        -e "s#src=\"\./$tag/#src=\"$raw#g" -e "s#src=\"${tag}/#src=\"$raw#g" "$notes"
    echo
    echo "----"
    echo
fi

echo "## Install"
echo
echo '```bash'
echo "pipx install git+https://github.com/$repo@$tag"
echo '```'
echo
echo "Or install the wheel attached below: \`pipx install ./pwndbg_imgui-${tag#v}-py3-none-any.whl\`."
echo
if [ -f "$notes" ]; then
    echo "## All changes"
else
    echo "## Changes"
fi
echo
git log --no-merges --format='- %s (%h)' "$range"
if [ -n "$prev" ]; then
    echo
    echo "**Full changelog:** https://github.com/$repo/compare/$prev...$tag"
fi
