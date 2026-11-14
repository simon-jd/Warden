# Existing guest-shell material candidate, not execution evidence

Controller ordinary-host read-only metadata/header/hash check at2026-10-25T00:44:33Z
authenticated `/usr/bin/dash`:root0:0/0755/nlink1/no xattrs,129856B,ELF64LE ET_DYN
machine62, SHA256c626229526bb58ec2d0f585f3c3ae1412e6f973b4353385042d11c38d8426917.
Installed authenticated readelf `--dynamic /usr/bin/dash` reports DT_NEEDED libc.so.6.
Only public file bytes and ELF declarations were read; the shell/attack was not
executed, copied, built or installed. This is not full loader/dependency closure,
publisher-signature/provenance, license validation or guest ABI/capacity proof.

The [metadata](metadata.json) records both input/tool hashes and bounded dynamic
output hash. A future independently reviewed material plan still needs actual
loader/libs/license/provenance, immutable image/artifact binding and32MiB FC fit.
Ordinaryguard/runtime gates remain. The existing task5 draft index is preserved;
this separate candidate index adds no executed matrix cells.
