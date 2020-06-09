# ctf

* https://capturetheflag.withgoogle.com/#beginners/

From radare2 docs: https://www.radare.org/n/radare2.html

```
$ r2 /bin/ls
> aaa    # analyze all the things
> is     # list symbols
> iz     # list strings
> afl    # list functions found
> pdf    # disassemble function
> s <tab># seek to address
> fs     # flag symbols
> v      # enter visual panels mode
```

* Commands I've ran:
```
r2 rand2

aaa
is
iz
afl

s sym.next_destination
pdf
```

What I've did:
1. Open the rand2 executable file in write mode in radare2

```
$ r2 -w rand2
```

2. Analysed

```
aaa
```

3. Seek main

```
s main
```

4. Open visual mode or `pdf` and seek strcmp condition:

```
 0x00000903      eb0e           jne 0x905
 ;-- panel.addr:
 0x00000905      488d3dd50100.  lea rdi, qword str.REDACTED    ; 0xae1 ; "<REDACTED>"
```

5. Rewrite condition to always skip that, like a `if(false){}` condition:

5.1. To rewrite use the `w` command:
```
[0x00000872]> s 0x0903
[0x00000903]> wa jmp 0x913
Written 2 byte(s) (jmp 0x913) = wx eb0e
```

```
 0x00000903      eb0e           jmp 0x913
 ;-- panel.addr:
 0x00000905      488d3dd50100.  lea rdi, qword str.REDACTED    ; 0xae1 ; "<REDACTED>"
```

6. After that the program started to print the CTF expected values:

```
./rand2
Travel coordinator
0: AC+79 3888 - 113685998930058, 111163805567206
1: Pliamas Sos - 62562492083311, 167272355811620
2: Ophiuchus - 170840919874774, 186843198798812
3: Pax Memor -ne4456 Hi Pro - 147886927342136, 186436032590962
4: Camion Gyrin - 229733986538799, 193411707343731
5: CTF - 209321211148877, 13822921949070

Enter your destination's x coordinate:
>>>
```


7. The redact values were printed, but unfortunately it didn't worked 😕.
I'll now try to decompile the next_destination function to check if I can generate the coordinates.

  7.1. Install r2dec plugin:

  ```
  r2pm init
  r2pm -i r2dec
  ```

  7.2. Decompile `next_destination` function:

  ```
  r2 rand2
  aaa
  s sym.next_destination
  pdd
  ```

  this is the function that have been decompiled:

  ```c
/* r2dec pseudo code output */
/* rand2 @ 0x81a */
#include <stdint.h>

int64_t next_destination (void) {
    rdx = *(obj.seed);
    rax = 0x5deece66d;
    rax *= rdx;
    rcx = rax + 0xb;
    edx = 0x10001;
    rax = rcx;
    rdx:rax = rax * rdx;
    rax = rcx;
    rax -= rdx;
    rax >>= 1;
    rax += rdx;
    rax >>= 0x2f;
    rdx = rax;
    rdx <<= 0x30;
    rdx -= rax;
    rax = rcx;
    rax -= rdx;
    *(obj.seed) = rax;
    rax = *(obj.seed);
    return rax;
}
  ```

  The function doesn't have any input parameters, it uses the value stored in `obj.seed`.
  Before trying evaluate it on a new small binary, I'd first have to know the type of that value.

  When I've checked the decompiled code from the main function, I can see that the coordinates are printed
  with this printf function:
  ```
    r2 rand2
    aaa
    s main
    ldd
  ```

  ```c
    printf ("%zu, %zu\n");
  ```

  ```
    z	For integer types, causes printf to expect a size_t-sized integer argument.
    u	Print decimal unsigned int.
  ```

  * I've tried to create a small program that would use the function and print the coordinates:

```c
/* r2dec pseudo code output */
/* rand2 @ 0x81a */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

typedef struct t_objs {
    size_t * seed;
} t_obj;
size_t * seed;

t_obj obj;

int64_t next_destination (void) {
    int64_t rdx = *(obj.seed);
    int64_t rax = 0x5deece66d;
    rax *= rdx;
    int64_t rcx = rax + 0xb;
    int64_t edx = 0x10001;
    rax = rcx;
    rdx:rax = rax * rdx;
    rax = rcx;
    rax -= rdx;
    rax >>= 1;
    rax += rdx;
    rax >>= 0x2f;
    rdx = rax;
    rdx <<= 0x30;
    rdx -= rax;
    rax = rcx;
    rax -= rdx;
    *(obj.seed) = rax;
    rax = *(obj.seed);
    return rax;
}

int main(int argc, char** argv){
    printf("hello world\n");
    size_t seed = 67197947526307;
    obj.seed = &seed;
    int64_t result = next_destination();
    printf("x = %zu\n", result);
    seed = result;
    obj.seed = &seed;
    result = next_destination();
    printf("y = %zu\n", result);
}
```

But unfortunately, the numbers didn't match as well.

8. My last try was to force my way into the printf.

Around success and failure messages there are two "JNE" commands that must check if the coordinate values are correct, otherwise jump to failure message:
```
Arrived somewhere, but not where the flag is. Sorry, try again.
```

```
# radare2 -w rand2
[0x00000710]> aaa
[0x00000710]> s main
[0x00000872]> pdf
```

At the end of the main:
```
|           0x000009a8      e86dfeffff     call sym.next_destination
|           0x000009ad      4889c2         mov rdx, rax
|           0x000009b0      488b45e0       mov rax, qword [var_20h]
|           0x000009b4      4839c2         cmp rdx, rax
|       ,=< 0x000009b7      7522           jne 0x9db
|       |   0x000009b9      b800000000     mov eax, 0
|       |   0x000009be      e857feffff     call sym.next_destination
|       |   0x000009c3      4889c2         mov rdx, rax
|       |   0x000009c6      488b45d8       mov rax, qword [var_28h]
|       |   0x000009ca      4839c2         cmp rdx, rax
|      ,==< 0x000009cd      750c           jne 0x9db
|      ||   0x000009cf      488d3d8a0100.  lea rdi, qword str.Arrived_at_the_flag._Congrats__your_flag_is:_CTF_welcome_to_googlectf ; 0xb60 ; "Arrived at the flag. Congrats, your flag is: CTF{welcome_to_googlectf}" ; const char *s
|      ||   0x000009d6      e8d5fcffff     call sym.imp.puts           ; int puts(const char *s)
|      ||   ; CODE XREFS from main @ 0x9b7, 0x9cd
|      ``-> 0x000009db      488d3dc60100.  lea rdi, qword str.Arrived_somewhere__but_not_where_the_flag_is._Sorry__try_again. ; 0xba8 ; "Arrived somewhere, but not where the flag is. Sorry, try again." ; const char *s
```

You can see the two `jne 0x9db` calls

I'll change both to `jmp 0x09cf`:

```
s 0x09b7
wa jmp 0x09cf
s 0x09cd
wa jmp 0x09cf
```

After that the flag message was printed:

```
# ./rand2
Travel coordinator
0: AC+79 3888 - 35520358608775, 98137850868274
1: Pliamas Sos - 45989707822162, 86182303540764
2: Ophiuchus - 74726921370802, 150583888635752
3: Pax Memor -ne4456 Hi Pro - 33417161033029, 73702861926831
4: Camion Gyrin - 154939921910499, 193773442989621
5: CTF - 56070244414536, 58478249910297

Enter your destination's x coordinate:
>>> 1
Enter your destination's y coordinate:
>>> 2
Arrived at the flag. Congrats, your flag is: CTF{welcome_to_googlectf}
Arrived somewhere, but not where the flag is. Sorry, try again.
```

9. Although I've had an idea all the way what the flag message should look like, I've still tried to use the expected values for x and y coordinates.

After analysed the binary and run the `iz` command in radare2, the strings were listed.

🤷‍♂️ Next step: find a way to fix `next_destination` decompiled function
