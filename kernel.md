# Kernel Pwn Cheat Sheet

## Kernel Version
```
commit 09688c0166e76ce2fb85e86b9d99be8b0084cdf9 (HEAD -> master, tag: v5.17-rc8, origin/master, origin/HEAD)
Author: Linus Torvalds <torvalds@linux-foundation.org>
Date:   Sun Mar 13 13:23:37 2022 -0700

    Linux 5.17-rc8
```
## Rturn to usermode
* [swapgs\_restore\_regs\_and\_return\_to\_usermode](https://github.com/torvalds/linux/blob/35ce8ae9ae2e471f92759f9d6880eab42cc1c3b6/arch/x86/entry/entry_64.S#L587)

## Structures

| structure        | slab      | flag               | memo                      |
|------------------|-----------|--------------------|---------------------------|
| shm\_file\_data  | 32        | GFP_KERNEL         |                           |
| seq\_operations  | 32        | GFP_KERNEL_ACCOUNT | /proc/self/stat           |
| msg\_msg         | 64 ~ 1024 | GFP_KERNEL_ACCOUNT |                           |
| msg\_msgseg      | 8 ~ 1024  | GFP_KERNEL_ACCOUNT |                           |
| subprocess\_info | 128       | GFP_KERNEL         | `socket(22, AF_INET, 0);` |
| timerfd\_ctx     | 256       | GFP_KERNEL         |                           |
| tty\_struct      | 1024      | GFP_KERNEL         | /dev/ptmx                 |
| pipe\_buffer     | 1024      | GFP_KERNEL_ACCOUNT |                           |
| setxattr         | 8 ~       | GFP_KERNEL         |                           |

### [shm\_file\_data](https://github.com/torvalds/linux/blob/85b6d24646e4125c591639841169baa98a2da503/ipc/shm.c#L83)
* [do\_shmat](https://github.com/torvalds/linux/blob/85b6d24646e4125c591639841169baa98a2da503/ipc/shm.c#L1608)

### [seq_operations](https://github.com/torvalds/linux/blob/359745d78351c6f5442435f81549f0207ece28aa/include/linux/seq_file.h#L32)
* [proc\_stat\_init](https://github.com/torvalds/linux/blob/a130e8fbc7de796eb6e680724d87f4737a26d0ac/fs/proc/stat.c#L239)
	* [stat\_proc\_ops](https://github.com/torvalds/linux/blob/a130e8fbc7de796eb6e680724d87f4737a26d0ac/fs/proc/stat.c#L229-L235)
* [stat\_open](https://github.com/torvalds/linux/blob/a130e8fbc7de796eb6e680724d87f4737a26d0ac/fs/proc/stat.c#L226)
	* [single\_open\_size](https://github.com/torvalds/linux/blob/372904c080be44629d84bb15ed5e12eed44b5f9f/fs/seq_file.c#L600)
		* [single\_open](https://github.com/torvalds/linux/blob/372904c080be44629d84bb15ed5e12eed44b5f9f/fs/seq_file.c#L575)
* [seq\_read\_iter](https://github.com/torvalds/linux/blob/372904c080be44629d84bb15ed5e12eed44b5f9f/fs/seq_file.c#L225)
	* `m->op->start`

### [msg\_msg](https://github.com/torvalds/linux/blob/34b56df922b10ac2876f268c522951785bf333fd/include/linux/msg.h#L9) / [msg\_msgseg](https://github.com/torvalds/linux/blob/137ec390fad41928307216ea9f91acf5cf6f4204/ipc/msgutil.c#L37)
* [do\_msgsnd](https://github.com/torvalds/linux/blob/18319498fdd4cdf8c1c2c48cd432863b1f915d6f/ipc/msg.c#L858)
	* [load\_msg](https://github.com/torvalds/linux/blob/137ec390fad41928307216ea9f91acf5cf6f4204/ipc/msgutil.c#L91)
		* [alloc\_msg](https://github.com/torvalds/linux/blob/137ec390fad41928307216ea9f91acf5cf6f4204/ipc/msgutil.c#L52-L75)
* [do\_msgrcv](https://github.com/torvalds/linux/blob/18319498fdd4cdf8c1c2c48cd432863b1f915d6f/ipc/msg.c#L1152-L1155)
	* `#define MSG_COPY 040000`

### [subprocess\_info](https://github.com/torvalds/linux/blob/55e6074e3fa67e1fb9ec140904db7e6cae6eda4b/include/linux/umh.h#L19)
* [\_\_sys\_socket](https://github.com/torvalds/linux/blob/0fc95dec096c2133942c382396172ae4487b4d57/net/socket.c#L1561)
	* sock_create
		* [\_\_sock\_create](https://github.com/torvalds/linux/blob/0fc95dec096c2133942c382396172ae4487b4d57/net/socket.c#L1449)
			* [\_\_request\_module](https://github.com/torvalds/linux/blob/17652f4240f7a501ecc13e9fdb06982569cde51f/kernel/kmod.c#L170)
				* [call\_modprobe](https://github.com/torvalds/linux/blob/17652f4240f7a501ecc13e9fdb06982569cde51f/kernel/kmod.c#L93)
					* [call\_usermodehelper\_setup](https://github.com/torvalds/linux/blob/48207f7d41c8bdae94d2aae11620ed76fee95d45/kernel/umh.c#L365)

### [timerfd\_ctx](https://github.com/torvalds/linux/blob/66f7b0c8aadd2785fc29f2c71477ebc16f4e38cc/fs/timerfd.c#L31)
* [timerfd\_create](https://github.com/torvalds/linux/blob/66f7b0c8aadd2785fc29f2c71477ebc16f4e38cc/fs/timerfd.c#L428)
* [timerfd\_release](https://github.com/torvalds/linux/blob/66f7b0c8aadd2785fc29f2c71477ebc16f4e38cc/fs/timerfd.c#L245)
	* `kfree_rcu`

### [tty\_struct](https://github.com/torvalds/linux/blob/4072254f96f954ec0d34899f15d987803b6d76a2/include/linux/tty.h#L195)
* [unix98\_pty\_init](https://github.com/torvalds/linux/blob/f6038cf46e376e21a689605e64ab5152e673ac7e/drivers/tty/pty.c#L937-L938)
	* [tty\_default\_fops](https://github.com/torvalds/linux/blob/d6d9d17abac8d337ecb052b47e918ca9c0b4ba1b/drivers/tty/tty_io.c#L3501-L3504)
		* [tty\_fops](https://github.com/torvalds/linux/blob/d6d9d17abac8d337ecb052b47e918ca9c0b4ba1b/drivers/tty/tty_io.c#L471-L484)
* [ptmx\_open](https://github.com/torvalds/linux/blob/f6038cf46e376e21a689605e64ab5152e673ac7e/drivers/tty/pty.c#L834)
	* [tty\_init\_dev](https://github.com/torvalds/linux/blob/d6d9d17abac8d337ecb052b47e918ca9c0b4ba1b/drivers/tty/tty_io.c#L1412)
		* [alloc\_tty\_struct](https://github.com/torvalds/linux/blob/d6d9d17abac8d337ecb052b47e918ca9c0b4ba1b/drivers/tty/tty_io.c#L3091)
* [tty\_ioctl](https://github.com/torvalds/linux/blob/d6d9d17abac8d337ecb052b47e918ca9c0b4ba1b/drivers/tty/tty_io.c#L2662-L2781)
	* [tty\_paranoia\_check](https://github.com/torvalds/linux/blob/d6d9d17abac8d337ecb052b47e918ca9c0b4ba1b/drivers/tty/tty_io.c#L268-L272)
		* `#define TTY_MAGIC 0x5401`
	* [tty\_pair\_get\_tty](https://github.com/torvalds/linux/blob/d6d9d17abac8d337ecb052b47e918ca9c0b4ba1b/drivers/tty/tty_io.c#L2645-L2646)
	* `tty->ops->ioctl`

### [pipe\_buffer](https://github.com/torvalds/linux/blob/1998f19324d24df7de4e74d81503b4299eb99e7d/include/linux/pipe_fs_i.h#L26)
* [do\_pipe2](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L1010)
	* [do\_pipe\_flags](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L962)
		* [create\_pipe\_files](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L913)
			* [get\_pipe\_inode](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L881-L888)
				* [alloc\_pipe\_info](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L785-L808)
			* [pipefifo\_fops](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L1218)
* [pipe\_release](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L734)
	* [put\_pipe\_info](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L711)
		* [free\_pipe\_info](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L844)
			* [pipe\_buf\_release](https://github.com/torvalds/linux/blob/1998f19324d24df7de4e74d81503b4299eb99e7d/include/linux/pipe_fs_i.h#L203)
				* `ops->release`

### setxattr
* [setxattr](https://github.com/torvalds/linux/blob/6961fed420146297467efe4bc022458818839a1a/fs/xattr.c#L563)


## Variables

| variable       | path                          |
|----------------|-------------------------------|
| modprobe\_path | /proc/sys/kernel/modprobe     |
| core\_pattern  | /proc/sys/kernel/core_pattern |

### modprobe\_path
* do\_execve
	* do\_execveat\_common
		* bprm\_execve
			* exec\_binprm
				* [search\_binary\_handler](https://github.com/torvalds/linux/blob/f0bc21b268c1464603192a00851cdbbf7c2cdc36/fs/exec.c#L1739-L1743)
					* [\_\_request\_module](https://github.com/torvalds/linux/blob/17652f4240f7a501ecc13e9fdb06982569cde51f/kernel/kmod.c#L170)
						* [call\_modprobe](https://github.com/torvalds/linux/blob/17652f4240f7a501ecc13e9fdb06982569cde51f/kernel/kmod.c#L93-L98)
							* call\_usermodehelper\_setup
							* call\_usermodehelper\_exec

### core\_pattern
* [do\_coredump](https://github.com/torvalds/linux/blob/f0bc21b268c1464603192a00851cdbbf7c2cdc36/fs/coredump.c#L565-L628)
	* [format\_corename](https://github.com/torvalds/linux/blob/f0bc21b268c1464603192a00851cdbbf7c2cdc36/fs/coredump.c#L199)
	* call\_usermodehelper\_setup
	* call\_usermodehelper\_exec
