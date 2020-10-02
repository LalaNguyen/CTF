import angr
import sys

path2bin = "./a.out"
project = angr.Project(path2bin)

# Ready for symbolic execution, we do not need to tell angr that std input is symbolic. By default, angr treats stdinput as a symbolic variable with 16 bytes */
initial_state = project.factory.entry_state()

# Initialize the angr engine 
simulation = project.factory.simgr(initial_state)

# Configure explore settings 

bad_addr = 0x401100   # Obtained during program analysis with Ghidra, the offset to the put("success") is 0x111d, 
good_addr = 0x40111d  # and angr loads our program at the base addr 0x400000
print('here')
simulation.explore(find=good_addr, avoid=bad_addr)
solution = simulation.found[0]
print(solution.posix.dumps(sys.stdin.fileno()))

