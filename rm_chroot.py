#!/usr/bin/env python3

# Removes a build directory or chroot copy on behalf of ALHP, which runs
# unprivileged and cannot remove root-owned chroot contents itself.
#
# Never build a shell command out of the argument: it contains a package name and
# version taken from upstream metadata, and this runs as root on every build
# teardown. Removal goes through shutil.rmtree, and the target is checked for
# containment rather than by string prefix.

import shutil
import sys
from pathlib import Path

SAVE_PATH = Path("/path/to/workdir")

try:
    save_path = SAVE_PATH.resolve(strict=True)
    target = Path(sys.argv[1]).resolve(strict=True)
except (IndexError, OSError):
    print("path does not resolve")
    sys.exit(1)

# is_relative_to, not startswith: a prefix test also accepts "/path/to/workdirevil".
# Refusing SAVE_PATH itself stops an empty or trailing-slash argument wiping the
# whole workspace.
if target == save_path or not target.is_relative_to(save_path):
    print("refusing to remove %s: outside %s" % (target, save_path))
    sys.exit(2)

shutil.rmtree(target)
