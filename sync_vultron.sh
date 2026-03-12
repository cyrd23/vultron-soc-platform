#!/usr/bin/env bash
set -euo pipefail

BRANCH="${1:-main}"

echo
echo "[+] Vultron sync helper"
echo "[+] Repo: $(pwd)"
echo "[+] Branch: ${BRANCH}"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "[!] Not inside a git repository."
  exit 1
fi

echo
echo "[+] Current status"
git status --short

if [[ -n "$(git status --porcelain)" ]]; then
  echo
  read -rp "[?] Local changes detected. Commit them now? [y/N]: " COMMIT_CHOICE

  if [[ "${COMMIT_CHOICE}" =~ ^[Yy]$ ]]; then
    git add .

    DEFAULT_MSG="Sync Vultron changes"
    read -rp "[?] Commit message [${DEFAULT_MSG}]: " COMMIT_MSG
    COMMIT_MSG="${COMMIT_MSG:-$DEFAULT_MSG}"

    git commit -m "${COMMIT_MSG}" || true
  else
    echo "[!] Aborting because local changes exist."
    exit 1
  fi
fi

echo
echo "[+] Fetching latest from origin"
git fetch origin

echo
echo "[+] Ensuring branch ${BRANCH} is checked out"
git checkout "${BRANCH}"

echo
echo "[+] Rebasing local branch on origin/${BRANCH}"
git pull --rebase origin "${BRANCH}"

echo
read -rp "[?] Push local branch to GitHub now? [y/N]: " PUSH_CHOICE
if [[ "${PUSH_CHOICE}" =~ ^[Yy]$ ]]; then
  git push origin "${BRANCH}"
fi

echo
echo "[+] Final status"
git status
echo
echo "[+] Recent commits"
git log --oneline -5
