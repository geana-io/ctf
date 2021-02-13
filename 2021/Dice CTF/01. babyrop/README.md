# babyrop

Original binary provide for the challenge is `babyrop`.

The `babyrop.patched` file was created using [patchelf][1].

```sh
cp babyrop babyrop.patched
patchelf --set-interpreter `pwd`/ld-linux-x86-64.so.2 babyrop.patched
patchelf --set-rpath `pwd` babyrop.patched
```

The exploit is based on the [return-to-csu approach][2]. The flag is
`dice{so_let's_just_pretend_rop_between_you_and_me_was_never_meant_b1b585695bdd0bcf2d144b4b}`.

[1]: https://github.com/NixOS/patchelf
[2]: https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf
