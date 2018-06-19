::
:: Copyright 2013-2018, Bromium, Inc.
:: SPDX-License-Identifier: ISC
::

set svcname=uxensf

copy /Y uxensf.sys %SystemRoot%\system32\drivers\uxensf.sys
if %errorlevel% neq 0 exit /b %errorlevel%

copy /Y uxenMRXNP.dll %SystemRoot%\system32\uxenMRXNP.dll
rem if %errorlevel% neq 0 exit /b %errorlevel%

sc create %svcname% binpath= system32\drivers\uxensf.sys type= filesys group= NetworkProvider DisplayName= %svcname% start= auto
if %errorlevel% neq 0 exit /b %errorlevel%

reg add HKLM\SYSTEM\CurrentControlSet\Services\%svcname%\NetworkProvider /v "DeviceName" /d "\Device\VBoxMiniRdr"
reg add HKLM\SYSTEM\CurrentControlSet\Services\%svcname%\NetworkProvider /v "Name" /d "uXen Hypervisor Shared Folders"
reg add HKLM\SYSTEM\CurrentControlSet\Services\%svcname%\NetworkProvider /v "ProviderPath" /d "%SystemRoot%\system32\uxenMRXNP.dll"

reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\control\networkprovider\order /v ProviderOrder /d %svcname%,RDPNP,LanmanWorkstation,webclient /f
