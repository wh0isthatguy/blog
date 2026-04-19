---
title: "rand() vulnerability"
date: 2023-05-12
draft: false
tags: ["rand", "pwn"]
showTableOfContents: true
---
{{< alert >}}
**Images not loading?** Try accessing this site using a VPN.
{{< /alert >}}

## Vấn đề
Giả sử ta có đoạn code sau đây được compile bằng `gcc -o rand rand.c`

```cpp=
#include <stdio.h>
int main()
{
        int input ;
        scanf("%d",&input) ;
        srand(time(NULL));
        if (rand() == input) system("/bin/sh");
        else puts("NOOB") ;
        return 0 ;
}
```

Mục đích của ta là làm sao để input bằng output của `rand()` trong C. Để giải quyết được bài toán này, ta sẽ tìm hiểu sơ lược về pseudorandom number generator (PRNG) cũng như cách hàm `rand()` được implement trong glibc.

## Điều gì làm một số random là một số random ?
### 1. Pseudorandom number generator
Hiểu một cách đơn giản, số random thực sự là một số được tạo ra hoàn toàn ngầu nhiên, không sinh ra dựa trên quy luật hay bất kỳ mục đích nào cả. Ví dụ đơn giản nhất chính là mật độ khí $O_2$ hiện tại trong phòng bạn, tiếng ồn ở một nơi bất kỳ, tung xí ngầu,... Và vì thế, các trường hợp mà bạn có khả năng điều khiển các dữ kiện gốc hay nói một cách khác là tạo ra dựa trên một quy luật, một thuật toán sinh nào đó thì được gọi là PRNG.

Để phục vụ nhu cầu tạo số random trên máy tính người ta đã đến với một giải pháp là sử dụng deterministic algorithm để tạo ra một số trong có vẻ là random nhưng thực chất là không random. Một trong những cách để implement nó chính là sử dụng linear congruential generator, và cách này được sài ở hàm rand() trong C.

### 2. Linear congruential generator (LCG)
Thuật toán này nhằm mục đích tạo ra một số random dựa trên một seed cho trước. Điều này đồng nghĩa với việc nếu ta lấy cùng một seed đó để sinh ra trong mỗi lần chạy chương trình thì vẫn được các số random ra y chang nhau.

Công thức truy hồi của LCG như sau:
$x_{n+1} = (ax_n + c) \mod m$

Trong đó : 
- $x_n$ là số random trước đó
- $x_{n+1}$ là số random sẽ được tạo ra
- $a, c, m$ là hằng số quyết định tính chất của số random
- $x_0$ là seed được cung cấp.

## rand() trong glibc

Hàm `rand()` trong C sẽ gọi tới`__random()` và `__random_r()` sẽ đảm nhận việc tạo ra số random

![](https://hackmd.io/_uploads/SyB-yEs43.png)

![](https://hackmd.io/_uploads/rJeukVoN2.png)

Trong đó, `__random_r()` sử dụng 2 cơ chế để random, single state (khúc trong if TYPE_0) và khúc multistate (mình tự gọi). 

Single state là thuật toán đơn giản vì chỉ sử dụng duy nhất một "kiểu" sinh. Thuật toán này có khuyết điểm là với một số nào đó được sinh ra thì ta sẽ gặp lại số đó sau $2^{31}$ lần gọi `rand()`. Cách này được gọi là `TYPE_0` trong source glibc.

Multistate cho phép ta gặp lại số trùng nhau do đã có một vài cải tiến so với thuật toán trên. State này hoạt động như sau : 

Với một seed s, và mảng $r_0...r_{33}$, số được sinh ra sẽ thoả:
- $r_0 = s$
- $r_i = (16807 \times (\text{signed int}) r_{i-1}) \mod 2147483647$ (i = 1 ... 30)
- $r_i = r_{i-31}$ (i = 31...33) 

Từ $r_{34}$ trở đi thuật toán sẽ thành:
- $r_i = (r_{i-3} + r_{i-31}) \mod 4294967296$ (i ≥ 34)

Kết quả hàm rand() thứ i sẽ là: $r_i + 344 >> 1$
Khi ta set seed bằng `srand()` thì sẽ mặc định sài cái multistate
Ta có code chạy multistate được viết lại như sau:
```cpp=
#include <stdio.h>

#define MAX 1000
#define seed SET_YOURS

main() {
  int r[MAX];
  int i;

  r[0] = seed;
  for (i=1; i<31; i++) {
    r[i] = (16807LL * r[i-1]) % 2147483647;
    if (r[i] < 0) {
      r[i] += 2147483647;
    }
  }
  for (i=31; i<34; i++) {
    r[i] = r[i-31];
  }
  for (i=34; i<344; i++) {
    r[i] = r[i-31] + r[i-3];
  }
  for (i=344; i<MAX; i++) {
    r[i] = r[i-31] + r[i-3];
    printf("%d\n", ((unsigned int)r[i]) >> 1);
  }
}

```

Nếu bạn compile rồi chạy thử code trên thì số được tạo ra sẽ y chang khi sài `rand()`
## Khai thác
Vậy ta đã biết sơ lược về cách hàm `rand()` hoạt động trong C. Với code đề bài đưa ra, ta có nhận xét là seed được tạo ra chính là thời điểm ta kết nối với server. Trong python có một thư viện hữu ích Ctypes, cho phép sử dụng các hàm có sẵn trong C (nếu bạn không thích sài thì code lại nguyên hàm `time()` cũng như `rand()` cũng được). Ở đây ta thấy `time()` sẽ được tính kể từ thời điểm chương trình gọi nó, do vậy khi code python ta chạy thì hên xui sẽ có một độ delay nhất định so với server. Do vậy nếu không được ta sẽ thử từng `time+1, time+2,...` để đồng bộ.

Script : 
```python=
from pwn import *
from ctypes import CDLL

libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
p = remote("localhost",6666)
libc.srand(libc.time(0))
p.sendline(str(libc.rand()))
p.interactive()
```
Ở đây hên là code mình đồng bộ với server luôn. Chạy và ta có được shell 

![](https://hackmd.io/_uploads/BkStiViN2.png)

## References
1. [The GLIBC random number generator](https://www.mscs.dal.ca/~selinger/random/)
2. [glibc rand function implementation](https://stackoverflow.com/questions/18634079/glibc-rand-function-implementation)
3. [rand() source](https://codebrowser.dev/glibc/glibc/stdlib/random_r.c.html#35buf)
