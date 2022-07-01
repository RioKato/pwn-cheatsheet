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
### Summary

| structure       | kmalloc |
|-----------------|---------|
| shm\_file\_data | 32      |
| seq\_operations | 32      |
| msg\_msg        | 64 ~ 1k |
| msg\_msgseg     | 8 ~ 1k  |
| timerfd\_ctx    | 256     |
| tty\_struct     | 1024    |
| setxattr        | 8 ~     |

### [shm\_file\_data](https://github.com/torvalds/linux/blob/85b6d24646e4125c591639841169baa98a2da503/ipc/shm.c#L83)
* [do\_shmat](https://github.com/torvalds/linux/blob/85b6d24646e4125c591639841169baa98a2da503/ipc/shm.c#L1608)

### [seq_operations](https://github.com/torvalds/linux/blob/359745d78351c6f5442435f81549f0207ece28aa/include/linux/seq_file.h#L32)
* [single\_open](https://github.com/torvalds/linux/blob/372904c080be44629d84bb15ed5e12eed44b5f9f/fs/seq_file.c#L575)

### [msg\_msg](https://github.com/torvalds/linux/blob/34b56df922b10ac2876f268c522951785bf333fd/include/linux/msg.h#L9-L16) / [msg\_msgseg](https://github.com/torvalds/linux/blob/137ec390fad41928307216ea9f91acf5cf6f4204/ipc/msgutil.c#L37-L40)
* [do\_msgsnd](https://github.com/torvalds/linux/blob/18319498fdd4cdf8c1c2c48cd432863b1f915d6f/ipc/msg.c#L858)
	* [load\_msg](https://github.com/torvalds/linux/blob/137ec390fad41928307216ea9f91acf5cf6f4204/ipc/msgutil.c#L91)
		* [alloc\_msg](https://github.com/torvalds/linux/blob/137ec390fad41928307216ea9f91acf5cf6f4204/ipc/msgutil.c#L52-L75)
* [do\_msgrcv](https://github.com/torvalds/linux/blob/18319498fdd4cdf8c1c2c48cd432863b1f915d6f/ipc/msg.c#L1152-L1155)
	* `#define MSG_COPY 040000`

### [timerfd\_ctx](https://github.com/torvalds/linux/blob/66f7b0c8aadd2785fc29f2c71477ebc16f4e38cc/fs/timerfd.c#L31)
* [timerfd\_create](https://github.com/torvalds/linux/blob/66f7b0c8aadd2785fc29f2c71477ebc16f4e38cc/fs/timerfd.c#L428)
* [timerfd\_release](https://github.com/torvalds/linux/blob/66f7b0c8aadd2785fc29f2c71477ebc16f4e38cc/fs/timerfd.c#L245)

### [tty\_struct](https://github.com/torvalds/linux/blob/4072254f96f954ec0d34899f15d987803b6d76a2/include/linux/tty.h#L195-L200)
* [unix98\_pty\_init](https://github.com/torvalds/linux/blob/f6038cf46e376e21a689605e64ab5152e673ac7e/drivers/tty/pty.c#L937-L938)
	* [tty\_default\_fops](https://github.com/torvalds/linux/blob/d6d9d17abac8d337ecb052b47e918ca9c0b4ba1b/drivers/tty/tty_io.c#L3501-L3504)
		* [tty\_fops](https://github.com/torvalds/linux/blob/d6d9d17abac8d337ecb052b47e918ca9c0b4ba1b/drivers/tty/tty_io.c#L471-L484)
* [ptmx\_open](https://github.com/torvalds/linux/blob/f6038cf46e376e21a689605e64ab5152e673ac7e/drivers/tty/pty.c#L834)
	* [tty\_init\_dev](https://github.com/torvalds/linux/blob/d6d9d17abac8d337ecb052b47e918ca9c0b4ba1b/drivers/tty/tty_io.c#L1412)
		* [alloc\_tty\_struct](https://github.com/torvalds/linux/blob/d6d9d17abac8d337ecb052b47e918ca9c0b4ba1b/drivers/tty/tty_io.c#L3091)
* [tty\_ioctl(1)](https://github.com/torvalds/linux/blob/d6d9d17abac8d337ecb052b47e918ca9c0b4ba1b/drivers/tty/tty_io.c#L2662-L2665)
	* [tty\_paranoia\_check](https://github.com/torvalds/linux/blob/d6d9d17abac8d337ecb052b47e918ca9c0b4ba1b/drivers/tty/tty_io.c#L268-L272)
		* `#define TTY_MAGIC 0x5401`
	* [tty\_pair\_get\_tty](https://github.com/torvalds/linux/blob/d6d9d17abac8d337ecb052b47e918ca9c0b4ba1b/drivers/tty/tty_io.c#L2645-L2646)
* [tty\_ioctl(2)](https://github.com/torvalds/linux/blob/d6d9d17abac8d337ecb052b47e918ca9c0b4ba1b/drivers/tty/tty_io.c#L2777-L2781)

### setxattr
* [setxattr](https://github.com/torvalds/linux/blob/6961fed420146297467efe4bc022458818839a1a/fs/xattr.c#L563-L577)


## Variables
### Summary

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

### core\_pattern
* [do\_coredump(1)](https://github.com/torvalds/linux/blob/f0bc21b268c1464603192a00851cdbbf7c2cdc36/fs/coredump.c#L565-L567)
	* [format\_corename](https://github.com/torvalds/linux/blob/f0bc21b268c1464603192a00851cdbbf7c2cdc36/fs/coredump.c#L199)
* [do\_coredump(2)](https://github.com/torvalds/linux/blob/f0bc21b268c1464603192a00851cdbbf7c2cdc36/fs/coredump.c#L623-L628)
