#!/bin/sh
# Needed for systems without gettext
rm -f /tmp/seabios-kconfig-check-sh.$$
cat >/tmp/seabios-kconfig-check-sh.$$ << EOF
#include <libintl.h>
int main()
{
	gettext("");
	return 0;
}
EOF
$* -xc -o /dev/null /tmp/seabios-kconfig-check-sh.$$ > /dev/null 2>&1
if [ ! "$?" -eq "0"  ]; then
	echo -DKBUILD_NO_NLS;
fi
rm -f /tmp/seabios-kconfig-check-sh.$$

