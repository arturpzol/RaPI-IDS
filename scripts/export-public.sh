#!/usr/bin/env bash
# Build the public branch: one commit, the committed tree minus what stays
# private.
#
#   scripts/export-public.sh [message]
#
# The repository here is the working one: the Polish development journal in
# docs/, the Polish README, and every commit that led to the code. None of that
# is for the public repository, and deleting it here would lose it. So the
# public branch is not a filtered copy of this history but a single commit
# with no parent, made from HEAD's tree with the private paths left out, and
# written again from scratch on every run. The working tree, the index and the
# current branch are not touched: the tree is assembled in a throwaway index.
#
# The branch is only created here. Pushing it is a separate, deliberate step:
#   git push <remote> public:main
set -euo pipefail

BRANCH="${RAPI_PUBLIC_BRANCH:-public}"
# Private: the journal and the Polish README.
PRIVATE=(docs README.md)
# The public README, written in English beside the Polish one and published
# under the name GitHub shows.
PUBLIC_README=README.en.md
# Words that only a Polish text would have, matched as whole words, as a last
# check that nothing private slipped in under another name. ASCII, like the
# texts themselves (they are written without diacritics).
POLISH='\b(jest|oraz|ktory|ktora|ktore|sie|wiec|tylko|przez|obraz|dziala|zeby|jesli)\b'  # polish-word-list

cd "$(git rev-parse --show-toplevel)"
git rev-parse --verify -q HEAD >/dev/null || { echo "no commit to export" >&2; exit 1; }

INDEX="$(mktemp)"
trap 'rm -f "$INDEX"' EXIT
export GIT_INDEX_FILE="$INDEX"
git read-tree HEAD
for path in "${PRIVATE[@]}"; do
  git rm -r --cached --quiet --ignore-unmatch -- "$path"
done
# No public README is not a README left out on purpose: the repository would
# go out with none at all.
blob="$(git rev-parse -q --verify "HEAD:$PUBLIC_README")" \
  || { echo "no $PUBLIC_README in HEAD, nothing exported" >&2; exit 1; }
git rm --cached --quiet -- "$PUBLIC_README"
git update-index --add --cacheinfo "100644,$blob,README.md"
TREE="$(git write-tree)"

# A README that is not finished yet: a placeholder where the account name goes
# (the install steps would point Imager at a 404), or a picture it shows that
# is not in the tree (a broken image on the project's front page).
readme="$(git show "$TREE:README.md")"
problems=""
if grep -q "OWNER/" <<<"$readme"; then
  problems+="  README.md still says OWNER where the GitHub account goes"$'\n'
fi
while read -r image; do
  [[ -z "$image" ]] && continue
  git cat-file -e "$TREE:$image" 2>/dev/null || problems+="  README.md shows $image, which is not in the tree"$'\n'
done < <(grep -oE '!\[[^]]*\]\([^)#?]+\)' <<<"$readme" | sed -E 's/.*\(([^)]+)\)/\1/' | grep -v '://')
if [[ -n "$problems" ]]; then
  echo "The public README is not finished, nothing exported:" >&2
  printf '%s' "$problems" >&2
  exit 1
fi

# The check runs on the tree that would be published, not on the directory.
# grep -c, not -q: -q stops at the first match, git show then dies of SIGPIPE,
# and under pipefail the pipeline fails exactly when a match was found. Every
# file past the pipe buffer (64 KiB) with a Polish word near its top passed.
leaks="$(git ls-tree -r --name-only "$TREE" \
  | grep -E '\.(md|txt|rst)$' \
  | while read -r file; do
      if git show "$TREE:$file" | grep -ciP "$POLISH" >/dev/null; then echo "$file"; fi
    done || true)"
if [[ -n "$leaks" ]]; then
  echo "Polish text would be published, nothing exported:" >&2
  echo "$leaks" | sed 's/^/  /' >&2
  exit 1
fi

# From the tree being published, not from the working copy, which may carry an
# uncommitted version bump that this commit does not contain.
VERSION="$(git show HEAD:backend/app/main.py 2>/dev/null | sed -n 's/^VERSION = "\(.*\)"$/\1/p')"
MESSAGE="${1:-RaPi IDS Panel ${VERSION:-(unversioned)}}"
COMMIT="$(git commit-tree "$TREE" -m "$MESSAGE")"
unset GIT_INDEX_FILE
git update-ref "refs/heads/$BRANCH" "$COMMIT"

echo "$BRANCH -> $(git rev-parse --short "$COMMIT"): one commit, $(git ls-tree -r --name-only "$COMMIT" | wc -l) files"
echo "left out: ${PRIVATE[*]}"
echo "publish with: git push <remote> $BRANCH:main"
