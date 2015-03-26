::
:: Copyright 2013-2015, Bromium, Inc.
:: SPDX-License-Identifier: ISC
::

set svcname=uxendmpdrv

copy /Y uxendmpdrv.sys %SystemRoot%\system32\drivers\uxendmpdrv.sys
if %errorlevel% neq 0 exit /b %errorlevel%

sc create %svcname% binpath= system32\drivers\uxendmpdrv.sys type= kernel start= system
if %errorlevel% neq 0 exit /b %errorlevel%

sc start uxendmpdrv
if %errorlevel% neq 0 exit /b %errorlevel%
