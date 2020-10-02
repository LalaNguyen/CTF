*****Knowledge**
- Assembly
- Understanding Program's Binary

**Task**: We are given a binary without source code. Our goal is to understand how this works and seize the flag.

**Investigation**:
We use Ghidra to decompile the binary. The logic is as follows:

```c
ulong main(void)

{
  int iVar1;
  uint uVar2;
  undefined auVar3 [16];
  undefined local_38 [16];
  undefined4 local_28;
  undefined4 uStack36;
  undefined4 uStack32;
  undefined4 uStack28;
  
  printf("Flag: ");
  __isoc99_scanf(&DAT_0010200b,local_38);
  auVar3 = pshufb(local_38,SHUFFLE);
  auVar3 = CONCAT412(SUB164(auVar3 >> 0x60,0) + ADD32._12_4_,
                     CONCAT48(SUB164(auVar3 >> 0x40,0) + ADD32._8_4_,
                              CONCAT44(SUB164(auVar3 >> 0x20,0) + ADD32._4_4_,
                                       SUB164(auVar3,0) + ADD32._0_4_))) ^ XOR;
  local_28 = SUB164(auVar3,0);
  uStack36 = SUB164(auVar3 >> 0x20,0);
  uStack32 = SUB164(XOR >> 0x40,0);
  uStack28 = SUB164(XOR >> 0x60,0);
  iVar1 = strncmp(local_38,(char *)&local_28,0x10);
  if (iVar1 == 0) {
    uVar2 = strncmp((char *)&local_28,EXPECTED_PREFIX,4);
    if (uVar2 == 0) {
      puts("SUCCESS");
      goto LAB_00101112;
    }
  }
  uVar2 = 1;
  puts("FAILURE");
LAB_00101112:
  return (ulong)uVar2;
}
```

In summary, the program takes stdinput (i.e., the flag), the flag is then recomputed with algorithmatic operations (i.e, shuffle, xor).
The flag's correctness is checked by two strncmp functions. It seems that our task is to produce the correct flag so that it reaches the puts("SUCCESS") line.
Otherwise, the execution falls through the put("Failure"). The key challenge here is to understand how the flag is recomputed, which took me 4 days to understand.
Alternatively, we can use symbolic execution to explore inputs that help us explore all the paths. In here, we have two paths, success or failure.

We use the following python script with angr to perform symbolic execution as follows:

```python
import angr
import sys

path2bin = "./a.out"
project = angr.Project(path2bin)

# Ready for symbolic execution, we do not need to tell angr that std input is symbolic. By default, angr treats stdinput as a symbolic variable with 16 bytes */
initial_state = project.factory.entry_state()

# Initialize the angr's symbolic engine 
simulation = project.factory.simgr(initial_state)

# Configure explore settings 

bad_addr = 0x401100   # Obtained during program analysis with Ghidra, the offset to the put("success") is 0x111d, 
good_addr = 0x40111d  # and angr loads our program at the base addr 0x400000

simulation.explore(find=good_addr, avoid=bad_addr)
solution = simulation.found[0]
print(solution.posix.dumps(sys.stdin.fileno()))
# Which gives us the flag: b'CTF{S1MDf0rM3!}'
```
