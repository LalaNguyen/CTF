***Baby_Mult***

***Knowledge****
- Reading Assembly

***Investigate***

We were given a ```program.txt``` which contains a sequence of integers. It seems these integers represent bytes of a program since the maximum integer is 255.
Once we disassembled the program, we obtained a seemingly valid asm program:

```bash
  ...
  3e:   48 b8 61 5b 64 4b cf    movabs rax, 0x77cf4b645b61
  45:   77 00 00
  48:   48 89 45 c8             mov    QWORD PTR [rbp-0x38], rax
  4c:   48 c7 45 c0 02 00 00    mov    QWORD PTR [rbp-0x40], 0x2
  53:   00
  54:   48 c7 45 b8 11 00 00    mov    QWORD PTR [rbp-0x48], 0x11
  5b:   00
  5c:   48 c7 45 b0 c1 21 00    mov    QWORD PTR [rbp-0x50], 0x21c1
  63:   00
  64:   48 c7 45 a8 e9 65 22    mov    QWORD PTR [rbp-0x58], 0x182265e9
  6b:   18
  6c:   48 c7 45 a0 33 08 00    mov    QWORD PTR [rbp-0x60], 0x833
  73:   00
  74:   48 c7 45 98 ab 0a 00    mov    QWORD PTR [rbp-0x68], 0xaab
  7b:   00
  7c:   48 c7 45 90 ad aa 8d    mov    QWORD PTR [rbp-0x70], 0x8daaad
  83:   00
  84:   48 8b 45 f8             mov    rax, QWORD PTR [rbp-0x8]
  88:   48 0f af 45 f0          imul   rax, QWORD PTR [rbp-0x10]
  8d:   48 89 45 88             mov    QWORD PTR [rbp-0x78], rax
  91:   48 8b 45 e8             mov    rax, QWORD PTR [rbp-0x18]
  95:   48 0f af 45 e0          imul   rax, QWORD PTR [rbp-0x20]
  9a:   48 0f af 45 d8          imul   rax, QWORD PTR [rbp-0x28]
  9f:   48 0f af 45 d0          imul   rax, QWORD PTR [rbp-0x30]
  a4:   48 0f af 45 c8          imul   rax, QWORD PTR [rbp-0x38]
```
We could have executed it and debug the output with gdb, but we did the multiplications instead. The multiplication seems to be discreeted, with 4 values stored at respective places: rbp-0x78, rbp-0x80, rbp-0x88, rbp-0x90.
Getting ascii out of hex value, we obtained the flag:flag{sup3r_v4l1d_pr0gr4m}

