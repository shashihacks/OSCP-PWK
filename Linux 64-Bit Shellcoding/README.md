###Reducing Instruction Size and Removing Nulls

1. In Shellcoding
    - Reduce the instruction size
    - Remove nulls (Null signifies end of string)

###Data Types
- Byte - 8 bits
- Word - 16 bits
- Double word - 32 bits
- Quad word - 64 bits
- Double Quad Word - 128 bits

###Nasm..
- Case sensitive syntax
- Accessing memory refernce with []
    - `message db 0xAA, 0xBB, 0xCC ... `(defines series of bytes with label ,`message`)
    - `mov rax, message` &larr;  moves address into `rax` 
    - `mov rax, [message]` &larr; moves value into `rax`    

#### Defining Initialized Data in NASM

|   Feature             |  Description          |
| --------------------  | -------------- |
| `db 0x55`             | Just the byte 0x55 |
| `db 0x55, 0x56, 0x57` | ghout the database. |
| `db 'a', 0x55`        |character constants are OK. |
| `db 'hello', 13,10, '$'` |so are string contants |
| `dw  0x1234`        |`0x34`    `0x12` |
| `dw  'a'`        |`0x61` ` 0x00 ` (It's just a number)|
| `dw  'ab'`        |`0x61`    `0x62`  (character constant)|
| `dw  'abc'`        |`0x61`    `0x62` `0x63`  (string)|
| `dw  0x12345678`        |`0x78`    `0x56` `0x34` `0x12`|

#### Defining Uninitialized Data in NASM

|   Feature             |  Description          |
| --------------------  | -------------- |
| `buffer: resb 64`             | Reserve 64 bytes|
| `wordvar: resw 1`             | Reserve a word|

#### Special Tokens

1. `$`- evaulates to the current line
1. `$$`- evaulates to the beginning of current section


#### Endianess

- Order in which bytes are stored

**Low address**  &emsp; &emsp;  &emsp;  &emsp;  &emsp;  &emsp;  &emsp;&emsp; &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;              **High address**
 Address|   0  |  1  | 2 | 3 |  4| 5 | 6 | 7 |
 | - | -    | -   | - | - | - | --|-- |-  |
 |**Little-endian**| Byte 0    |Byte 1   |Byte 2  | Byte 3  | Byte 4  | Byte 5 |Byte 6 |Byte 7  |
 |**Big-endian**  | Byte 7    |Byte 6   |Byte 5  | Byte 4  | Byte 3  | Byte 2 |Byte 1 |Byte 0  |

<br></br>
**Memory content**
|   `0x11`  |  `0x22`  | `0x33`|`0x44` |  `0x55`| `0x66` | `0x77` | `0x88` |
| -    | -   | - | - | - | --|-- |-  |
**64 bit value in Little-endian**
|   `0x8877665544332211`  | 
| -    | 
**64 bit value in Big-endian**
|   `0x1122334455667788`  | 
| -    | 


 ```
 x86 and x86_x64  both uses Littl-endian format
 ```


### Assembly Code

#### Sample code
``` nasm
global _start  
section .text 

;start like main
_start:
		mov rax, 1     ;  1 for write to screen
		mov rdi, 1     ;  1 for write to screen
		mov rsi, hello_world
		mov rdx, length
		syscall
		; exit gracefully
		mov rax, 60     ;60 for exit
		mov rdi, 11     ; exit code can be anything 0 OR 1 OR any 
		syscall  ; system call

section .data
	hello_world: db 'Hello World to the Pentester academy'
	length: equ $-hello_world ; calculate the length of the hello_world


```

- complie steps
```
    nasm -felf64 HelloWorld.nasm -o HelloWorld.o 
    ld HelloWorld.o -o HelloWorld     //linking
    ./HelloWorld
```


- `rax` takes 48 bytes
-  comand used to display through object dump
`objdump -M intel -d HelloWorld.o`
``` b
HelloWorld.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <_start>:
   0:   b8 01 00 00 00          mov    eax,0x1
   5:   bf 01 00 00 00          mov    edi,0x1
   a:   48 be 00 00 00 00 00    movabs rsi,0x0
  11:   00 00 00 
  14:   ba 24 00 00 00          mov    edx,0x24
  19:   0f 05                   syscall 
  1b:   b8 3c 00 00 00          mov    eax,0x3c
  20:   bf 0b 00 00 00          mov    edi,0xb
  25:   0f 05                   syscall 

```


- Variables (Datatypes)
``` nasm

global _start  
section .text 

;start like main
_start:
		mov rax, 1     ;  1 for write
		mov rdi, 1     ;  1 for write
		mov rsi, hello_world
		mov rdx, length
		syscall

		mov rax, var4
		mov rax, [var4]

		; exit gracefully
		mov rax, 60     ;60 for exit
		mov rdi, 11     ; exit code can be anything 0 OR 1 OR any 
		syscall  ; system call

section .data
	hello_world: db 'Hello World to the Pentester academy'
	length: equ $-hello_world ; calculate the length of the hello_world

	var1: db 0x11, 0x22  ; define bytes
	var2: dw 0x3344      ; word
	var3: dd 0xaabbccdd    ; 4 bytes
	var4: dq 0xaabbccdd11223344 ; 8bytes

	repaet_buffer: times 128 db 0xAA

section .bss ; reserving uninitiliazed datra
	buffer: resb 64 ; reserve 64 bytes

```


### GDB TUI Mode
- TUI (Test User Interface)

`gdb -q ./HelloWorld -tui  ` to open in TUI mode

<br></br>
#### MOV

- Most common instruiction in ASM
- Allowed directions
    - Between Registers
    - Memmory to Register and Register to Memory
    - Immediate Data to Register
    - Immediate Data to Memory


#### LEA
- Moad Effective address - load pointer values
- `LEA RAX, [label]`

#### XCHG
- Exchange (swap) values
- `XCHG Register, Register`
- `XCHG Register, Memory`



### The Stack

- A temporary location in memory where we can store data, while the program is running
- High level programming languages like C , make extensive use of stack
- Stack operations consists of two operations
  - `PUSH` - insert data into the stack
  - `POP` - Remove data from the stack

![Stack as Lifo](https://raw.githubusercontent.com/shashihacks/oscp-new/master/Linux%2064-Bit%20Shellcoding/assets/stack.jpeg?token=AD4TE56ZE7QA36EE6PQI57TAOFLFM)

Sample `Stack.nasm` program


```nasm

;Purpose: Stack instruction in 64 bit CPU

global _start

section .text
_start:
	mov rax, 0x1122334455667788 ; move immediate value into rax
	push rax   ; push the value contained in rax to stack

	push sample   ; address reeferenceby sample i.e db 0xaa....

	push qword [sample]  ; pickup 8 bytes, interpret as qword  and push into stack

	pop r15
	pop r14
	pop rbx

	; exit program

	mov rax, 0x3c
	mov rdi, 0
	syscall

section .data

sample : db 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22
```

**Compile:** `nasm Stack.nasm -o Stack.o`
**Link:**    `ld Stack.o -o Stack`
**Opening in tui mode:** `gdb -q ./Stack -tui`
<br></br><br></br><br></br><br></br><br></br><br></br>
<br></br><br></br><br></br><br></br><br></br><br></br>
<br></br><br></br><br></br><br></br><br></br><br></br><br></br><br></br><br></br><br></br><br></br><br></br>



 



































