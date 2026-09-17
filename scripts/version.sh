#!/bin/sh
#
# Output the current version number
#

usage() {
    echo "Usage: $0 [date|short|hash]"
    echo
    echo "Determine the correct version number for the current build"
    exit 0
}

# We assume this script is in the TOPDIR/scripts directory and use that
# to find any other files we need
TOPDIR=$(dirname "$0")/..

VER_FILE_SHORT=$(cat "${TOPDIR}/VERSION")

if [ -n "$N2N_VERSION_DATE" ] && [ -n "$N2N_VERSION_HASH" ]; then
    # OpenWrt's PKG_SOURCE_PROTO:=git download step (git clone + git archive
    # into a tarball) strips .git from the extracted PKG_BUILD_DIR, so the
    # "real" branch below never actually runs for any OpenWrt cross-compile
    # -- every such build silently fell back to the bare-VERSION-file branch
    # at the bottom instead, with no date/hash at all, for the whole
    # lifetime of this fork. The packages Makefile now sets PKG_SOURCE_DATE
    # next to PKG_SOURCE_VERSION whenever it bumps the latter (both come
    # from this same repo's `git log`/`git rev-parse` at edit time) and
    # passes them in through these two env vars from its Build/Configure
    # step, reproducing exactly what the git-checkout branch below would
    # have computed if .git had survived.
    VER_SHORT="$VER_FILE_SHORT"
    VER_HASH="$N2N_VERSION_HASH"
    DATE="$N2N_VERSION_DATE"
    VER="${VER_FILE_SHORT}-${N2N_VERSION_DATE}-g${N2N_VERSION_HASH}"
elif (cd "$TOPDIR" 2>/dev/null && git rev-parse --is-inside-work-tree >/dev/null 2>&1); then
    # `-d "$TOPDIR/.git"` used to gate this branch, but a git *worktree*
    # (e.g. `git worktree add`, the standard way this fork's feature
    # branches get built/tested -- see feat/ipv6-stage-a's own dev flow)
    # has a .git *file* (a "gitdir: ..." pointer), not a directory, so that
    # check silently failed for every worktree checkout and fell all the
    # way through to the bare-VERSION-file branch below -- the exact "just
    # 3.1.1, no date/hash" symptom this whole rework exists to fix, and it
    # was happening even in plain native builds, not just OpenWrt's
    # .git-stripping git-archive download (see the env-var branch above).
    # `git rev-parse --is-inside-work-tree` correctly recognizes both a
    # regular checkout and a worktree.

    cd "$TOPDIR" || exit 1

    # NOTE: this used to require an annotated tag exactly matching the VERSION
    # file (via `git describe --abbrev=0`) and would print/embed a hard error
    # string as the version instead of failing the build outright if the tag
    # was missing or stale -- one bad tag anywhere in the repo's history silently
    # poisoned PACKAGE_VERSION into every binary built from that checkout with
    # no build failure to catch it. Building the version string directly from
    # VERSION + date + short hash needs no tag bookkeeping and can't drift.
    VER_SHORT="$VER_FILE_SHORT"
    VER_HASH=$(git rev-parse --short HEAD)
    DATE=$(git log -1 --format=%cd)
    VER="${VER_FILE_SHORT}-$(git log -1 --format=%cd --date=format:%Y%m%d)-g${VER_HASH}"
    if ! git diff --quiet HEAD -- 2>/dev/null || ! git diff --cached --quiet HEAD -- 2>/dev/null; then
        VER="${VER}-dirty"
    fi
else
    # If there is no .git directory in our TOPDIR, we fall back on relying on
    # the VERSION file

    VER_SHORT="$VER_FILE_SHORT"
    VER_HASH="HEAD"
    VER="$VER_FILE_SHORT"
    DATE=$(date)
fi

case "$1" in
    date)
        echo "$DATE"
        ;;
    hash)
        echo "$VER_HASH"
        ;;
    short)
        echo "$VER_SHORT"
        ;;
    "")
        echo "$VER"
        ;;
    *)
        usage
        ;;
esac
