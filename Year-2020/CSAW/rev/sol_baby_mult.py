from pwn import *

# 1st Stage: Analyzing the program.txt
ifile = open("program.txt","r")
arr = ifile.readlines()[0].rstrip("/n").split(",")
arr = [int(i) for i in arr]
# Convert the integer array to bytearrys
bytearr = bytearray(arr)

# Disassemble the arr
ostr = disasm(bytearr, arch="amd64")

print(ostr)
"""
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
  a9:   48 89 45 80             mov    QWORD PTR [rbp-0x80], rax
  ad:   48 8b 45 c0             mov    rax, QWORD PTR [rbp-0x40]
  b1:   48 0f af 45 b8          imul   rax, QWORD PTR [rbp-0x48]
  b6:   48 0f af 45 b0          imul   rax, QWORD PTR [rbp-0x50]
  bb:   48 0f af 45 a8          imul   rax, QWORD PTR [rbp-0x58]
  c0:   48 89 85 78 ff ff ff    mov    QWORD PTR [rbp-0x88], rax
  c7:   48 8b 45 a0             mov    rax, QWORD PTR [rbp-0x60]
  cb:   48 0f af 45 98          imul   rax, QWORD PTR [rbp-0x68]
  d0:   48 0f af 45 90          imul   rax, QWORD PTR [rbp-0x70]
  d5:   48 89 85 70 ff ff ff    mov    QWORD PTR [rbp-0x90], rax
  dc:   b8 00 00 00 00          mov    eax, 0x0
  e1:   c9                      leave
"""
# 2nd Stage: Do the multiplication
var08 = 0x4f
var10 = 0x14be74f15
var18 = 0x4
var20 = 0x3
var28 = 0x13
var30 = 0x115
var38 = 0x77cf4b645b61
var40 = 0x2
var48 = 0x11
var50 = 0x21c1
var58 = 0x182265e9
var60 = 0x833
var68 = 0xaab
var70 = 0x8daaad
var78 = var08*var10
var80 = var18*var20*var28*var30*var38
var88 = var40*var48*var50*var58
var90 = var60*var68*var70

# The flag seems to be segmented into var78, var80, var88, var90
'''
>>> bytes.fromhex(hex(var80)[2:])
b'sup3r_v4'
>>> bytes.fromhex(hex(var88)[2:])
b'l1d_pr'
>>> bytes.fromhex(hex(var90)[2:])
b'0gr4m}'
>>> bytes.fromhex(hex(var78)[2:])
b'flag{'
'''
flag = [var78,var80,var88,var90]
for part in flag:
    print(bytes.fromhex(hex(part)[2:]).decoded('ascii'))

# The flag is flag{sup3r_v4l1d_pr0gr4m}
ifile.close()

