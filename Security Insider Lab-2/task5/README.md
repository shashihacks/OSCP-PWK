### EXERCISE 1

1.

Compiling c source code with gcc
```bash
$: gcc A.c -o a.out
```

__Errors detected :__

![heap_block_overrun](../task5/images/heap_block_overrun.PNG)

__Category of error :__ Heap block overrun

__Fix:__
Change the allocates size to 11. (`line no: 6`)
```c
    x = (char *) malloc(11 * sizeof(char));
```
- Recompiled the  code with fix.
__Result:__

```bash
==89660== HEAP SUMMARY:
==89660==     in use at exit: 0 bytes in 0 blocks
==89660==   total heap usage: 1 allocs, 1 frees, 11 bytes allocated
==89660== 
==89660== All heap blocks were freed -- no leaks are possible
==89660== 
==89660== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```


2. 

Compiling c source code with gcc
```bash
$: gcc B.c -o b.out
```
__Errors detected :__

1. Memory unfreed
2. Accessing unalloacted byte

![haep_overrun_unfreed](../task5/images/haep_overrun_unfreed.PNG)

__Category of error :__ 
1. Heap block overrun
2. Memory leak  -- x is not freed

__Fix :__

```c
int main() {
        char *x;
        x = (char *) malloc(11 * sizeof(char)); //allocated size 11
        x[10] = 'A';
        free(x);  //freed allocated memory
        return 0;
}
```

__Result__

```bash
==89772== 
==89772== HEAP SUMMARY:
==89772==     in use at exit: 0 bytes in 0 blocks
==89772==   total heap usage: 1 allocs, 1 frees, 11 bytes allocated
==89772== 
==89772== All heap blocks were freed -- no leaks are possible
==89772== 
==89772== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)

```
