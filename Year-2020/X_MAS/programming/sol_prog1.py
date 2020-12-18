from pwn import *

HOST,PORT="challs.xmas.htsp.ro", 6051;
r = remote(HOST,PORT)
i = 0
k1 = 0
k2 = 0
arr = []
while(True):
    resp = r.recvuntil('\n')
    print(resp)
    if(b'k2 =' in resp):
        k2 = [int(s) for s in resp.split() if s.isdigit()][0]
        arr.sort()
        k1_smallest = arr[:k1]
        arr.sort(reverse=True)
        k2_smallest = arr[:k2]
        k1_smallest = [str(i) for i in k1_smallest]
        k2_smallest = [str(i) for i in k2_smallest]
        ans = str.encode(', '.join(k1_smallest)+'; '+', '.join(k2_smallest))
        r.sendline(ans)
    if(b'array =' in resp):
        arr = []
        #print(resp.decode('ascii').split())
        for s in resp.decode('ascii').split():
            s = s.replace(',','').replace('[','').replace(']','')
            if s.isdigit():
                arr.append(int(s))
    if(b'k1 =' in resp):
        k1 = [int(s) for s in resp.split() if s.isdigit()][0]
