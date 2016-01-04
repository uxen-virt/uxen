#!/bin/sh
# Script to generate a C file with version information.
OUTFILE="$1"
VAR16MODE="$2"

# Extract version info
if [ -e ../../.git ]; then
    VERSION="`git log --pretty=format:%H -n 1`"
    if ! `git diff --quiet`; then
        VERSION="${VERSION}-dirty"
    fi
else
    if [ -f .version ]; then
        VERSION="`cat .version`"
    else
        VERSION="?"
    fi
    VERSION="${VERSION}-`date +"%Y%m%d_%H%M%S"`-`hostname`"
fi
echo "Version: ${VERSION}"

# Build header file
if [ "$VAR16MODE" = "VAR16" ]; then
    cat > ${OUTFILE} <<EOF
#include "types.h"
char VERSION[] VAR16 = "${VERSION}";
EOF
else
    cat > ${OUTFILE} <<EOF
char VERSION[] = "${VERSION}";
EOF
fi
