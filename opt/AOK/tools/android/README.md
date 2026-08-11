# Running an Android system tree under iSH-AOK

Two scripts, one for each way of running a tree. `docs/android-bringup.md` in
the repo is the full story; this is what you need on the device.

## In a chroot, from an ordinary Alpine session

The route to use while booting the tree *as* a root is still not working, and
the one to start with either way: an Alpine session stays available to debug
from, and a bad step costs you a re-run rather than a locked-out app.

```sh
sh /AOK/tools/android/chroot-setup.sh /root/android-sys
chroot /root/android-sys /system/bin/sh
```

Run the setup script once per iSH launch, before chrooting. Mounts and the
property area do not survive an app restart; the device nodes and the linker
symlink do, so those steps are no-ops the second time.

Inside, the first things worth checking:

```sh
getprop                      # if this lists properties, bionic read our area
getprop servicemanager.ready # true
/system/bin/servicemanager & # start it BEFORE anything that talks to it
service list
```

After editing a `build.prop`, rebuild the property area without leaving the
shell -- from inside the chroot, this resolves against the chroot's own root,
so it reads that tree's files and rewrites that tree's area:

```sh
echo / > /proc/ish/property_area
cat /proc/ish/property_area
```

A process that already started keeps the area it mapped, so restart the
process too.

## As an iSH root

`root-profile.sh` is the session profile: copy it into the tree as
`/android-profile.sh` and point Settings -> Launch Command at

    /system/bin/sh /android-profile.sh

iSH does most of the setup itself at boot for a root -- `/proc`, `/sys`,
`/dev/pts`, the binder/ashmem/dma_heap nodes and `/dev/__properties__` -- so
the profile only fixes up the environment and one mount.

Two things bite before you get that far, and both read as something else:

- **Do not leave Boot Command at `/sbin/init`.** Android has no `/sbin/init`,
  and iSH's fallback list starts with `/init`, which in an Android image is
  Android's real init: it runs as pid 1, tries to mount fstab partitions and
  start ueventd, and dies there.
- **`/system/bin/linker64` must exist.** It is `PT_INTERP` for every binary,
  and a missing interpreter makes `execve` return ENOENT naming *the binary
  you ran*, not the interpreter -- which reads as "the shell is missing" when
  the shell is fine. Modern images ship the real one at
  `system/bin/bootstrap/linker64` and expect init to have linked it.

If a bad launch command locks you out: iOS Settings -> iSH-AOK -> **Recovery
Mode**, which boots the settings UI instead of a session. Do not delete the
app; that destroys the tree.
