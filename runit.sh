#!/bin/sh
/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm installed
