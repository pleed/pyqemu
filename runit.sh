#!/bin/sh
#sudo rm -f /usr/lib/python2.6/*.pyc
sudo rm -rf /usr/lib/python2.6/pyqemu
sudo make install
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm installed
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm heuristics
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm aescrypt
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm openssh
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm curl
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm context
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm winrar
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm threadtest
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm consttest
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm consttest2
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm consttest3
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm openssl-test
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm evaluation
#/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm evaluation2
/usr/local/bin/qemu -hda /home/matenaar/pyqemu_vm.img -m 2048 -net user -net nic,model=pcnet -loadvm evaluation3
