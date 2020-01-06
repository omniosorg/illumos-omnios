
######################################################################
# OmniOS-specific overrides

# Enable the non-DEBUG build
NIGHTLY_OPTIONS=${NIGHTLY_OPTIONS/F/}

export PERL_VERSION=5.30
export PERL_PKGVERS=
export PERL_VARIANT=-thread-multi
export BUILDPERL32='#'

export JAVA_ROOT=/usr/jdk/openjdk1.8.0
export JAVA_HOME=$JAVA_ROOT
export BLD_JAVA_7='#'
export BLD_JAVA_8=

export BUILDPY2=
export BUILDPY3=
export BUILDPY2TOOLS=
export BUILDPY3TOOLS=
export PYTHON3_VERSION=3.7
export PYTHON3_PKGVERS=-37
export TOOLS_PYTHON=/usr/bin/python$PYTHON3_VERSION

export ON_CLOSED_BINS=/opt/onbld/closed

# On OmniOS, gcc resides in /opt/gcc-<version> - adjust variables
export GNUC_ROOT=/opt/gcc-7/
for name in PRIMARY_CC PRIMARY_CCC SHADOW_CCS SHADOW_CCCS; do
        typeset -n var=$name
        var="`echo $var | sed '
                s^/usr/gcc^/opt/gcc^
                s^/opt/gcc/^/opt/gcc-^
        '`"
done

ENABLE_SMB_PRINTING='#'

export ONNV_BUILDNUM=`grep '^VERSION=r' /etc/os-release | cut -c10-15`
export PKGVERS_BRANCH=$ONNV_BUILDNUM.0

