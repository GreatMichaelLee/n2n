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

if [ -d "$TOPDIR/.git" ]; then
    # If there is a .git directory in our TOPDIR, then this is assumed to be
    # real git checkout

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
