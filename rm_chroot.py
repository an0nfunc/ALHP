#!/usr/bin/env python3

import os
import sys
from pathlib import Path

SAVE_PATH = "/path/to/workdir"

try:
    chroot_abs = Path(sys.argv[1]).resolve(True)
except:
    print("path does not resolve")
    sys.exit(1)

if str(chroot_abs).startswith(SAVE_PATH):
    os.system("rm -rf " + str(chroot_abs))
else:
    sys.exit(2)
