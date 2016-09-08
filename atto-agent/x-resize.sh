#!/bin/sh

XRANDR=/usr/bin/xrandr
CVT=/usr/bin/cvt

xres=$1
yres=$2

modeline=$($CVT -r $xres $yres | tail -n1 | sed -e 's/^[^"]*"[^"]*"//')

export DISPLAY=":0.0"
omode=0
if [ "$("$XRANDR" | grep \* | grep mode1)" == "" ]; then
    omode=1
fi
$XRANDR --delmode uxen mode$omode
$XRANDR --rmmode mode$omode
$XRANDR --newmode mode$omode $modeline
$XRANDR --addmode uxen mode$omode
$XRANDR --output uxen --mode mode$omode
