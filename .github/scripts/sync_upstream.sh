#!/usr/bin/env bash
set -euo pipefail

: "${UPSTREAM_REPO:?UPSTREAM_REPO is required}"
: "${UPSTREAM_BRANCH:?UPSTREAM_BRANCH is required}"
: "${TARGET_BRANCH:?TARGET_BRANCH is required}"
: "${FORCE_REBUILD:=false}"

case "$UPSTREAM_REPO" in
  [A-Za-z0-9._-]*/[A-Za-z0-9._-]*) ;;
  *) echo "上游仓库格式无效"; exit 1 ;;
esac
case "$UPSTREAM_BRANCH" in
  ""|*[!A-Za-z0-9._/-]*) echo "上游分支格式无效"; exit 1 ;;
esac
case "$TARGET_BRANCH" in
  ""|*[!A-Za-z0-9._/-]*) echo "目标分支格式无效"; exit 1 ;;
esac

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

upstream_url="${UPSTREAM_URL:-https://github.com/$UPSTREAM_REPO.git}"
if git remote get-url upstream >/dev/null 2>&1; then
  git remote set-url upstream "$upstream_url"
else
  git remote add upstream "$upstream_url"
fi

write_changed_output() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf 'changed=%s\n' "$1" >> "$GITHUB_OUTPUT"
  fi
}

refresh_from_origin() {
  # A workflow rerun checks out the original event SHA, which can be behind
  # master after an earlier attempt has already pushed a sync commit.
  git fetch origin "$TARGET_BRANCH"
  git reset --hard "origin/$TARGET_BRANCH"
}

restore_protected_paths() {
  for protected in .github/workflows .github/scripts tools/starflow; do
    if git ls-tree -d HEAD -- "$protected" | grep -q .; then
      git restore --source=HEAD --staged --worktree -- "$protected"
    fi
    git clean -fd -- "$protected"
  done
}

merge_upstream() {
  echo "检测到上游变化，开始合并"
  if ! git merge --no-ff --no-commit "upstream/$UPSTREAM_BRANCH"; then
    git merge --abort || true
    echo "上游合并冲突，已停止；没有自动覆盖冲突文件"
    exit 1
  fi

  restore_protected_paths
  git add -A
  if ! git diff --cached --quiet; then
    git commit -m "chore: sync upstream source data"
  elif git rev-parse -q --verify MERGE_HEAD >/dev/null; then
    echo "合并后没有可同步的非保护文件，取消合并"
    git merge --abort
  fi
}

upstream_source_unchanged() {
  # Compare only changes introduced on the upstream side since the common
  # ancestor. Target-only commits and protected paths must not retrigger sync.
  git diff --quiet "HEAD...upstream/$UPSTREAM_BRANCH" -- \
    . \
    ':(exclude).github/workflows' \
    ':(exclude).github/scripts' \
    ':(exclude)tools/starflow'
}

refresh_from_origin
git fetch upstream "$UPSTREAM_BRANCH"

if upstream_source_unchanged; then
  if [ "$FORCE_REBUILD" != "true" ]; then
    write_changed_output false
    echo "上游无变化，跳过生成和发布"
    exit 0
  fi
  echo "强制重新生成"
else
  source_changed=true
  merge_upstream

  pushed=false
  for attempt in 1 2 3; do
    if git push origin "HEAD:$TARGET_BRANCH"; then
      pushed=true
      break
    fi

    if [ "$attempt" -eq 3 ]; then
      echo "远端分支持续更新，重试 3 次后仍无法推送"
      exit 1
    fi

    echo "远端分支已更新，重新基于最新远端重放同步（第 $((attempt + 1)) 次尝试）"
    refresh_from_origin
    git fetch upstream "$UPSTREAM_BRANCH"
    if upstream_source_unchanged; then
      echo "远端已包含本次上游同步，继续生成和发布"
      pushed=true
      break
    fi
    merge_upstream
  done

  if [ "$pushed" != "true" ]; then
    echo "上游同步未推送"
    exit 1
  fi
fi

write_changed_output true
echo "同步完成，后续步骤将在同一次运行内执行"
