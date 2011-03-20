#!/bin/sh
/usr/local/bin/qemu -hda /home/matenaar/windows.img -m 1024 -net user -net nic,model=pcnet -loadvm test
