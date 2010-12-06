#!/usr/bin/env python

from symbols import *

handler = DLLHandler("/media/shared/")
handler.loadDLL("Cmdline.dll", 1024)
dll, function = handler.resolveToName(1000000000000)
print dll
print function
