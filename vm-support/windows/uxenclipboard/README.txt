This is the guest side of the uxen shared clipboard code.
Compile with nmake. Requires cl.exe to be in $PATH.
Add the following lines to vm json config file:
    "vmfwd" : {
        "proto" : "tcp",
        "host_port" : 44445,
        "host_service" : {
            "service" : "shared-clipboard"
        }
     },
     "vmfwd" : {
        "proto" : "tcp",
        "host_port" : 44446,
        "host_service" : {
            "service" : "shared-clipboard-hostmsg"
        }
     }
Copy VBoxClipboard.exe to the guest and run it.

