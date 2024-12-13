
######################################################################
# OmniOS-specific overrides

# Enable the non-DEBUG build
NIGHTLY_OPTIONS=${NIGHTLY_OPTIONS/F/}

export ON_CLOSED_BINS=/opt/onbld/closed

# On OmniOS, gcc resides in /opt/gcc-<version> - adjust variables
for name in PRIMARY_CC PRIMARY_CCC SHADOW_CCS SHADOW_CCCS; do
        typeset -n var=$name
        var="`echo $var | sed '
                s^/usr/gcc^/opt/gcc^
                s^/opt/gcc/^/opt/gcc-^
        '`"
done

ENABLE_SMB_PRINTING='#'

_branch=`git -C $CODEMGR_WS rev-parse --abbrev-ref HEAD`
_hash=`git -C $CODEMGR_WS rev-parse --short HEAD`
export VERSION=`echo omnios-$_branch-$_hash | tr '/' '-'`

export ONNV_BUILDNUM=`grep '^VERSION=r' /etc/os-release | cut -c10-15`
export PKGVERS_BRANCH=$ONNV_BUILDNUM.0

