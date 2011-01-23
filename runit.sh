#!/bin/sh
#/usr/local/bin/qemu -hda /home/felix/Projects/lehrstuhl_bonn/winxp_network.img -m 1024 -net user -net nic,model=pcnet -loadvm infected_twice
#/usr/local/bin/qemu -hda /home/felix/Projects/lehrstuhl_bonn/winxp_network.img -m 1024 -net user -net nic,model=pcnet -loadvm putty
#/usr/local/bin/qemu -hda /home/felix/Projects/lehrstuhl_bonn/winxp_network.img -m 1024 -net user -net nic,model=pcnet -loadvm updates_off
#/usr/local/bin/qemu -hda /home/felix/Projects/lehrstuhl_bonn/winxp_network.img -m 1024 -net user -net nic,model=pcnet -loadvm curl
/usr/local/bin/qemu -hda /home/felix/Projects/lehrstuhl_bonn/winxp_network.img -m 1024 -net user -net nic,model=pcnet -loadvm aescrypt
#/usr/local/bin/qemu -hda /home/felix/Projects/lehrstuhl_bonn/winxp_network.img -m 1024 -net user -net nic,model=pcnet -loadvm fileencrypter
