# Taosc integration

`recipe.scm` here is a Guix script to build taosc and fetch the bug exploits,
then print the recipe to demo its integration with DIBE.  For example,
from this repository's root directory (../..),

```console
$ guix time-machine -C third_party/taosc/channels.scm -- repl -- third_party/taosc/recipe.scm
Usage: third_party/taosc/recipe.scm BUG-ID WORKDIR

BUG-ID is one of the following:
CVE-2017-14940
CVE-2017-15025
CVE-2016-3623
CVE-2016-10266
CVE-2016-10267
CVE-2017-7595
CVE-2017-5980
CVE-2017-5981
$ guix time-machine -C third_party/taosc/channels.scm -- repl -- third_party/taosc/recipe.scm CVE-2017-5980 third_party/taosc/CVE-2017-5980
# PoC exploit
/gnu/store/i59fnk7chp52p8mqhcvfj41afs98061c-zziplib-static-0.13.62/bin/unzzipcat-mem /gnu/store/0qrqxj2pw6x2b0vrnypc8lk1jlwz3frh-bux-2026.09.14/share/bux/cve/2017/5980/null-deref.zip
# Patch generation
taosc-fix 10 third_party/taosc/CVE-2017-5980 /gnu/store/0qrqxj2pw6x2b0vrnypc8lk1jlwz3frh-bux-2026.09.14/share/bux/cve/2017/5980 /gnu/store/i59fnk7chp52p8mqhcvfj41afs98061c-zziplib-static-0.13.62/bin/unzzipcat-mem @@
# Launch exploit with DIBE
DIBE_PIDFILE=./pidfile DIBE_START_GATE=1 LD_PRELOAD=./patcher.so /gnu/store/i59fnk7chp52p8mqhcvfj41afs98061c-zziplib-static-0.13.62/bin/unzzipcat-mem /gnu/store/0qrqxj2pw6x2b0vrnypc8lk1jlwz3frh-bux-2026.09.14/share/bux/cve/2017/5980/null-deref.zip
# On another shell
# Coordinate PID
printf '{"pid": %d}\n' $(< ./pidfile) > micro_patch.json
# Send patch
./e9patch < third_party/taosc/CVE-2017-5980/unzzipcat-mem.brpatched.json
# Apply patch
echo APPLY > /tmp/dibe_ctrl.$(< ./pidfile)
```
