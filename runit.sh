#!/bin/sh
sudo rm -f /usr/lib/python2.6/*.pyc
sudo make install
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm installed
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm heuristics
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm aescrypt
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm openssh
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm curl
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm context
/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm winrar
