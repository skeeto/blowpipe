#!/bin/sh

# This script computes the Blowfish initialization tables using POSIX
# bc, or using the pi command if it is available (which is much faster
# than GNU bc).

set -e

if $(command -v pi > /dev/null 2>&1); then
    pi=$(echo "obase=16; $(pi 10040)" | bc | tr -d '\n\\' | tail -c+3)
else
    cmd='obase=16; scale=10040; a(1) * 4'
    pi="$(echo "$cmd" | bc -l | tr -d '\n\\' | tail -c+3)"
fi
ints="$(echo $pi | tr A-F a-f | head -c8336 | sed -r 's/.{8}/0x\0,\\n/g')"

echo 'static const uint32_t blowfish_p[] = {'
printf $ints | head -n18 | \
    paste -d ' ' - - - - | sed 's/^/    /g'
echo '};'
echo

echo 'static const uint32_t blowfish_s[] = {'
printf $ints | tail -n+19 | head -n1024 | \
    paste -d ' ' - - - - | sed 's/^/    /g'
echo '};'
