const DPINST_INSTALLED = &H0000FFFF

set sh = WScript.CreateObject("WScript.Shell")
rc = sh.Run (WScript.Arguments.Item(0),0,true)
if (rc and DPINST_INSTALLED) > 0 then
    rc = 0
end if
WScript.Quit(rc)
