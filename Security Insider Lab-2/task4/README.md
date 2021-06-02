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


last5 characters
(gdb) print hello
$12 = 0x555555556008 "Hello world!"


```