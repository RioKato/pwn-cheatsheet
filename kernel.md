# Kernel Pwn Cheat Sheet

- [Kernel version](#kernel-version)
- [Kernel config](#kernel-config)
- [Process management](#process-management)
	- [task\_struct](#task_struct)
	- [current](#current)
- [Syscall](#syscall)
- [Memory allocator](#memory-allocator)
	- [kmem\_cache](#kmem_cache)
	- [kmalloc](#kmalloc)
	- [kfree](#kfree)
- [Physmem](#physmem)
- [Paging](#paging)
- [Copy from/to user](#copy-fromto-user)
- [Symbol](#symbol)
- [Snippet](#snippet)
- [Structures](#structures)
	- [ldt\_struct](#ldt_struct)
	- [shm\_file\_data](#shm_file_data)
	- [seq_operations](#seq_operations)
	- [msg\_msg, msg\_msgseg](#msg_msg-msg_msgseg)
	- [subprocess\_info](#subprocess_info)
	- [timerfd\_ctx](#timerfd_ctx)
	- [pipe\_buffer](#pipe_buffer)
	- [tty\_struct](#tty_struct)
	- [setxattr](#setxattr)
	- [sk\_buff](#sk_buff)
- [Variables](#variables)
	- [modprobe\_path](#modprobe_path)
	- [core\_pattern](#core_pattern)
	- [poweroff\_cmd](#poweroff_cmd)
	- [n\_tty\_ops](#n_tty_ops)


## Kernel version
```
commit 09688c0166e76ce2fb85e86b9d99be8b0084cdf9 (HEAD -> master, tag: v5.17-rc8, origin/master, origin/HEAD)
Author: Linus Torvalds <torvalds@linux-foundation.org>
Date:   Sun Mar 13 13:23:37 2022 -0700

    Linux 5.17-rc8
```

## Kernel config

| config                        | memo                                       |
| ----------------------------- | ------------------------------------------ |
| CONFIG_KALLSYMS               | /proc/sys/kernel/kptr_restrict             |
| CONFIG_USERFAULTFD            | /proc/sys/vm/unprivileged_userfaultfd      |
| CONFIG_STATIC_USERMODEHELPER  |                                            |
| CONFIG_SLUB                   | default allocator                          |
| CONFIG_SLAB                   |                                            |
| CONFIG_SLAB_FREELIST_RANDOM   |                                            |
| CONFIG_SLAB_FREELIST_HARDENED |                                            |
| CONFIG_FG_KASLR               |                                            |
| CONFIG_BPF                    | /proc/sys/kernel/unprivileged_bpf_disabled |
| CONFIG_SMP                    | multi-processor                            |
| CONFIG_HAVE_STACKPROTECTOR    | cannary                                    |
| CONFIG_RANDOMIZE_BASE         | kaslr                                      |
| CONFIG_HARDENED_USERCOPY      | prevent copying beyond the size of object  |


## Process management

### task\_struct

* [task\_struct](https://github.com/torvalds/linux/blob/67d6212afda218d564890d1674bab28e8612170f/include/linux/sched.h#L728)
	* [thread\_info](https://github.com/torvalds/linux/blob/5443f98fb9e06e765e24f9d894bf028accad8f71/arch/x86/include/asm/thread_info.h#L56)
		* `syscall_work`
	* [cred](https://github.com/torvalds/linux/blob/c54b245d011855ea91c5beff07f1db74143ce614/include/linux/cred.h#L110)
	* `tasks`
		* [init\_task](https://github.com/torvalds/linux/blob/71f8de7092cb2cf95e3f7055df139118d1445597/init/init_task.c#L64)
			* [init\_cred](https://github.com/torvalds/linux/blob/a55d07294f1e9b576093bdfa95422f8119941e83/kernel/cred.c#L41)
	* `comm`
		* `prctl(PR_SET_NAME, name);`

### current

* [current](https://github.com/torvalds/linux/blob/b24413180f5600bcb3bb70fbed5cf186b60864bd/arch/x86/include/asm/current.h#L18)
	* [get\_current](https://github.com/torvalds/linux/blob/b24413180f5600bcb3bb70fbed5cf186b60864bd/arch/x86/include/asm/current.h#L15)
		* [current\_task](https://github.com/torvalds/linux/blob/b24413180f5600bcb3bb70fbed5cf186b60864bd/arch/x86/include/asm/current.h#L11)
			* [DECLARE\_PER\_CPU](https://github.com/torvalds/linux/blob/06c8839815ac7aa2b44ea3bb3ee1820b08418f55/include/linux/percpu-defs.h#L112)
				* [DECLARE\_PER\_CPU\_SECTION](https://github.com/torvalds/linux/blob/06c8839815ac7aa2b44ea3bb3ee1820b08418f55/include/linux/percpu-defs.h#L101)
					* [\_\_PCPU\_ATTRS](https://github.com/torvalds/linux/blob/06c8839815ac7aa2b44ea3bb3ee1820b08418f55/include/linux/percpu-defs.h#L50-L51)
						* *case CONFIG\_SMP*
							* [PER\_CPU\_BASE\_SECTION](https://github.com/torvalds/linux/blob/29813a2297910d5c4be08c7b390054f23dd794a5/include/asm-generic/percpu.h#L55)
		* [this\_cpu\_read\_stable](https://github.com/torvalds/linux/blob/4719ffecbb0659faf1fd39f4b8eb2674f0042890/arch/x86/include/asm/percpu.h#L226)
			* [\_\_pcpu\_size\_call\_return](https://github.com/torvalds/linux/blob/06c8839815ac7aa2b44ea3bb3ee1820b08418f55/include/linux/percpu-defs.h#L324)
				* [this\_cpu\_read\_stable_8](https://github.com/torvalds/linux/blob/4719ffecbb0659faf1fd39f4b8eb2674f0042890/arch/x86/include/asm/percpu.h#L225)
					* [percpu\_stable\_op](https://github.com/torvalds/linux/blob/4719ffecbb0659faf1fd39f4b8eb2674f0042890/arch/x86/include/asm/percpu.h#L154)
						* *case CONFIG\_SMP*
							* `movq %%gs:%P[var], %[val]` where `var = &current_task`
* [start\_kernel](https://github.com/torvalds/linux/blob/2dba5eb1c73b6ba2988ced07250edeac0f8cbf5a/init/main.c#L954)
	* [setup\_per\_cpu\_areas](https://github.com/torvalds/linux/blob/20c035764626c56c4f6514936b9ee4be0f4cd962/arch/x86/kernel/setup_percpu.c#L171-L215)
		* *case CONFIG\_SMP*
			* [per\_cpu\_offset](https://github.com/torvalds/linux/blob/29813a2297910d5c4be08c7b390054f23dd794a5/include/asm-generic/percpu.h#L21)
			* `__per_cpu_offset[cpu] = pcpu_base_addr - __per_cpu_start + pcpu_unit_offsets[cpu]`
		* [switch\_to\_new\_gdt](https://github.com/torvalds/linux/blob/25f8c7785e254779fbd2127c4eced81811e8e421/arch/x86/kernel/cpu/common.c#L645)
			* [load\_percpu\_segment](https://github.com/torvalds/linux/blob/25f8c7785e254779fbd2127c4eced81811e8e421/arch/x86/kernel/cpu/common.c#L605)
				* [cpu\_kernelmode\_gs\_base](https://github.com/torvalds/linux/blob/03b122da74b22fbe7cd98184fa5657a9ce13970c/arch/x86/include/asm/processor.h#L448)
					* [fixed\_percpu\_data](https://github.com/torvalds/linux/blob/03b122da74b22fbe7cd98184fa5657a9ce13970c/arch/x86/include/asm/processor.h#L443)
						* [DECLARE\_PER\_CPU\_FIRST](https://github.com/torvalds/linux/blob/06c8839815ac7aa2b44ea3bb3ee1820b08418f55/include/linux/percpu-defs.h#L122)
						* [fixed\_percpu\_data](https://github.com/torvalds/linux/blob/03b122da74b22fbe7cd98184fa5657a9ce13970c/arch/x86/include/asm/processor.h#L430)
					* [per\_cpu](https://github.com/torvalds/linux/blob/06c8839815ac7aa2b44ea3bb3ee1820b08418f55/include/linux/percpu-defs.h#L269)
						* *case CONFIG\_SMP*
							* [per\_cpu\_ptr](https://github.com/torvalds/linux/blob/06c8839815ac7aa2b44ea3bb3ee1820b08418f55/include/linux/percpu-defs.h#L236)
								* [SHIFT\_PERCPU\_PTR](https://github.com/torvalds/linux/blob/06c8839815ac7aa2b44ea3bb3ee1820b08418f55/include/linux/percpu-defs.h#L231)
									* [RELOC\_HIDE](https://github.com/torvalds/linux/blob/bfb1a7c91fb7758273b4a8d735313d9cc388b502/include/linux/compiler.h#L177)
					* *case CONFIG\_SMP*
						* `gs = &fixed_percpu_data.gs_base + __per_cpu_offset[cpu]`


## Syscall

* [entry\_SYSCALL\_64](https://github.com/torvalds/linux/blob/35ce8ae9ae2e471f92759f9d6880eab42cc1c3b6/arch/x86/entry/entry_64.S#L87)
	* [pt\_regs](https://github.com/torvalds/linux/blob/c6b01dace2cd7f6b3e9174d4d1411755608486f1/arch/x86/include/asm/ptrace.h#L59)
		* `pt_regs` may be use for stack pivoting
	* [do\_syscall\_64](https://github.com/torvalds/linux/blob/1dfb0f47aca11350f45f8c04c3b83f0e829adfa9/arch/x86/entry/common.c#L73)
		* `add_random_kstack_offset();`
		* [syscall\_enter\_from\_user\_mode](https://github.com/torvalds/linux/blob/6ce895128b3bff738fe8d9dd74747a03e319e466/kernel/entry/common.c#L108)
			* [\_\_syscall\_enter\_from\_user\_work](https://github.com/torvalds/linux/blob/6ce895128b3bff738fe8d9dd74747a03e319e466/kernel/entry/common.c#L90)
				* [syscall\_trace\_enter](https://github.com/torvalds/linux/blob/6ce895128b3bff738fe8d9dd74747a03e319e466/kernel/entry/common.c#L67-L71)
					* `SYSCALL_WORK_SECCOMP`
		* [do\_syscall\_x64](https://github.com/torvalds/linux/blob/1dfb0f47aca11350f45f8c04c3b83f0e829adfa9/arch/x86/entry/common.c#L50)
	* [swapgs\_restore\_regs\_and\_return\_to\_usermode](https://github.com/torvalds/linux/blob/35ce8ae9ae2e471f92759f9d6880eab42cc1c3b6/arch/x86/entry/entry_64.S#L587)


## Memory allocator

### kmem\_cache

* *case CONFIG\_SLUB*
	* [kmem\_cache](https://github.com/torvalds/linux/blob/40f3bf0cb04c91d33531b1b95788ad2f0e4062cf/include/linux/slub_def.h#L90)
		* [kmem\_cache\_cpu](https://github.com/torvalds/linux/blob/40f3bf0cb04c91d33531b1b95788ad2f0e4062cf/include/linux/slub_def.h#L49-L51)
			* `freelist`
			* [slab](https://github.com/torvalds/linux/blob/e3a8b6a1e70c37702054ae3c7c07ed828435d8ee/mm/slab.h#L35-L37)
				* `slab_cache`
				* `freelist`
		* `offset`
		* `random`
		* [kmem\_cache\_node](https://github.com/torvalds/linux/blob/e3a8b6a1e70c37702054ae3c7c07ed828435d8ee/mm/slab.h#L746)
* *case CONFIG\_SLAB*
	* [kmem\_cache](https://github.com/torvalds/linux/blob/40f3bf0cb04c91d33531b1b95788ad2f0e4062cf/include/linux/slab_def.h#L12)
		* [array\_cache](https://github.com/torvalds/linux/blob/6e48a966dfd18987fec9385566a67d36e2b5fc11/mm/slab.c#L185)
			* `entry`
		* [kmem\_cache\_node](https://github.com/torvalds/linux/blob/e3a8b6a1e70c37702054ae3c7c07ed828435d8ee/mm/slab.h#L746)
			* `shared`

### kmalloc

* [kmalloc](https://github.com/torvalds/linux/blob/93dd04ab0b2b32ae6e70284afc764c577156658e/include/linux/slab.h#L581-L583)
	* [kmalloc\_index](https://github.com/torvalds/linux/blob/93dd04ab0b2b32ae6e70284afc764c577156658e/include/linux/slab.h#L414)
		* [\_\_kmalloc\_index](https://github.com/torvalds/linux/blob/93dd04ab0b2b32ae6e70284afc764c577156658e/include/linux/slab.h#L369-L370)
			* *case CONFIG\_SLUB*
				* `#define KMALLOC_MIN_SIZE 8`
			* *case CONFIG\_SLAB*
				* `#define KMALLOC_MIN_SIZE 32`
	* [kmalloc\_caches](https://github.com/torvalds/linux/blob/f56caedaf94f9ced5dbfcdb0060a3e788d2078af/mm/slab_common.c#L674-L675)
	* [kmalloc\_type](https://github.com/torvalds/linux/blob/93dd04ab0b2b32ae6e70284afc764c577156658e/include/linux/slab.h#L332)
		* `#define GFP_KERNEL_ACCOUNT (GFP_KERNEL | __GFP_ACCOUNT)`
		* `GFP_KERNEL` &rarr; `KMALLOC_NORMAL`
		* `GFP_KERNEL_ACCOUNT` &rarr; `KMALLOC_CGROUP`
	* *case CONFIG\_SLUB*
		* [kmem\_cache\_alloc\_trace](https://github.com/torvalds/linux/blob/9c01e9af171f13cf6573f404ecaf96dfa48233ab/mm/slub.c#L3253)
			* [slab\_alloc](https://github.com/torvalds/linux/blob/9c01e9af171f13cf6573f404ecaf96dfa48233ab/mm/slub.c#L3238)
				* [slab\_alloc\_node](https://github.com/torvalds/linux/blob/9c01e9af171f13cf6573f404ecaf96dfa48233ab/mm/slub.c#L3165-L3198)
					* [\_\_slab\_alloc](https://github.com/torvalds/linux/blob/9c01e9af171f13cf6573f404ecaf96dfa48233ab/mm/slub.c#L3105)
						* [\_\_\_slab\_alloc](https://github.com/torvalds/linux/blob/9c01e9af171f13cf6573f404ecaf96dfa48233ab/mm/slub.c#L2895-L2896)
							* `slab = c->slab = slub_percpu_partial(c);`
							* [new\_slab](https://github.com/torvalds/linux/blob/9c01e9af171f13cf6573f404ecaf96dfa48233ab/mm/slub.c#L2004-L2005)
								* [allocate\_slab](https://github.com/torvalds/linux/blob/9c01e9af171f13cf6573f404ecaf96dfa48233ab/mm/slub.c#L1970)
									* [shuffle\_freelist](https://github.com/torvalds/linux/blob/9c01e9af171f13cf6573f404ecaf96dfa48233ab/mm/slub.c#L1878)
					* [get\_freepointer\_safe](https://github.com/torvalds/linux/blob/9c01e9af171f13cf6573f404ecaf96dfa48233ab/mm/slub.c#L369-L371)
						* [freelist\_ptr](https://github.com/torvalds/linux/blob/9c01e9af171f13cf6573f404ecaf96dfa48233ab/mm/slub.c#L334-L335)
						* `get_freepointer_safe(cache, object) = (object + cache->offset) ^ *(object + cache->offset) ^ cache->random`
	* *case CONFIG\_SLAB*
		* [kmem\_cache\_alloc\_trace](https://github.com/torvalds/linux/blob/6e48a966dfd18987fec9385566a67d36e2b5fc11/mm/slab.c#L3561)
			* [slab\_alloc](https://github.com/torvalds/linux/blob/6e48a966dfd18987fec9385566a67d36e2b5fc11/mm/slab.c#L3289-L3290)
				* [\_\_do\_cache\_alloc](https://github.com/torvalds/linux/blob/6e48a966dfd18987fec9385566a67d36e2b5fc11/mm/slab.c#L3257-L3258)
					* [\_\_\_\_cache\_alloc](https://github.com/torvalds/linux/blob/6e48a966dfd18987fec9385566a67d36e2b5fc11/mm/slab.c#L3023)
						* [cache\_alloc\_refill](https://github.com/torvalds/linux/blob/6e48a966dfd18987fec9385566a67d36e2b5fc11/mm/slab.c#L2891)
					* [\_\_\_\_cache_alloc_node](https://github.com/torvalds/linux/blob/6e48a966dfd18987fec9385566a67d36e2b5fc11/mm/slab.c#L3156)
						* [cache\_grow\_begin](https://github.com/torvalds/linux/blob/6e48a966dfd18987fec9385566a67d36e2b5fc11/mm/slab.c#L2618)
							* [cache\_init\_objs](https://github.com/torvalds/linux/blob/6e48a966dfd18987fec9385566a67d36e2b5fc11/mm/slab.c#L2496)
								* [shuffle\_freelist](https://github.com/torvalds/linux/blob/6e48a966dfd18987fec9385566a67d36e2b5fc11/mm/slab.c#L2432)

### kfree

* *case CONFIG\_SLUB*
	* [kfree](https://github.com/torvalds/linux/blob/9c01e9af171f13cf6573f404ecaf96dfa48233ab/mm/slub.c#L4562)
		* [slab\_free](https://github.com/torvalds/linux/blob/9c01e9af171f13cf6573f404ecaf96dfa48233ab/mm/slub.c#L3510)
			* [do\_slab\_free](https://github.com/torvalds/linux/blob/9c01e9af171f13cf6573f404ecaf96dfa48233ab/mm/slub.c#L3432-L3434)
				* `likely(slab == c->slab)` &rarr; `likely(slab == slab->slab_cache->cpu_slab->slab)`
				* [\_\_slab\_free](https://github.com/torvalds/linux/blob/9c01e9af171f13cf6573f404ecaf96dfa48233ab/mm/slub.c#L3300-L3302)
					* [set\_freepointer](https://github.com/torvalds/linux/blob/9c01e9af171f13cf6573f404ecaf96dfa48233ab/mm/slub.c#L379-L383)
						* `BUG_ON(object == fp);`
					* `put_cpu_partial(s, slab, 1);`
* *case CONFIG\_SLAB*
	* [kfree](https://github.com/torvalds/linux/blob/6e48a966dfd18987fec9385566a67d36e2b5fc11/mm/slab.c#L3794)
		* [\_\_\_cache\_free](https://github.com/torvalds/linux/blob/6e48a966dfd18987fec9385566a67d36e2b5fc11/mm/slab.c#L3448)
			* [cache\_flusharray](https://github.com/torvalds/linux/blob/6e48a966dfd18987fec9385566a67d36e2b5fc11/mm/slab.c#L3367)
			* [\_\_free\_one](https://github.com/torvalds/linux/blob/6e48a966dfd18987fec9385566a67d36e2b5fc11/mm/slab.c#L596-L599)
				* `WARN_ON_ONCE(ac->avail > 0 && ac->entry[ac->avail - 1] == objp)`


## Physmem

* [page tables](https://github.com/torvalds/linux/blob/251a7b3edc197a3947b8cb56fffe61d811aba0a5/Documentation/x86/x86_64/mm.rst#L45-L50)
	* `page_offset_base`
		* heap base address (by kmalloc) and it is mapped to `/dev/mem`
		* `secondary_startup_64` can be found at `page_offset_base + offset`
	* `vmalloc_base`
	* `vmemmap_base`

## Paging

* `CR3`, `Page Global Directory`, `Page Upper Directory`, `Page Middle Directory`, `Page Table Entry` are used
* each register or variable holds an encoded pointer, not a raw pointer
* the 12~51 bits of each register or valiable indicates the base address of the next directory
* see [5.3.3 4-Kbyte Page Translation / AMD64 Architecture Programmer's Manual, Volume 2](doc/AMD64_Architecture_Programmers_Manual_Volume2.pdf#page=203) for details
* last byte of `Page Global Directory(PML4E)` often be 0x67(0b01100111)

## Copy from/to user

* [copy\_from\_user](https://github.com/torvalds/linux/blob/a7a08b275a8bbade798c4bdaad07ade68fe7003c/include/linux/uaccess.h#L191)
	* [check\_copy\_size](https://github.com/torvalds/linux/blob/7ad639840acf2800b5f387c495795f995a67a329/include/linux/thread_info.h#L232)
		* *case CONFIG_HARDENED_USERCOPY*
			* [check\_object\_size](https://github.com/torvalds/linux/blob/7ad639840acf2800b5f387c495795f995a67a329/include/linux/thread_info.h#L199)
				* [\_\_check\_object\_size](https://github.com/torvalds/linux/blob/0b3eb091d5759479d44cb793fad2c51ea06bdcec/mm/usercopy.c#L287)
					* [check\_heap\_object](https://github.com/torvalds/linux/blob/0b3eb091d5759479d44cb793fad2c51ea06bdcec/mm/usercopy.c#L241)
						* *case CONFIG_HARDENED_USERCOPY*
							* *case CONFIG\_SLUB*
								* [\_\_check\_heap\_object](https://github.com/torvalds/linux/blob/9c01e9af171f13cf6573f404ecaf96dfa48233ab/mm/slub.c#L4488-L4489)
							* *case CONFIG\_SLAB*
								* [\_\_check\_heap\_object](https://github.com/torvalds/linux/blob/6e48a966dfd18987fec9385566a67d36e2b5fc11/mm/slab.c#L4172-L4173)
						* *otherwise*
							* [\_\_check\_heap\_object](https://github.com/torvalds/linux/blob/e3a8b6a1e70c37702054ae3c7c07ed828435d8ee/mm/slab.h#L861-L863)
						* [check\_page\_span](https://github.com/torvalds/linux/blob/0b3eb091d5759479d44cb793fad2c51ea06bdcec/mm/usercopy.c#L161-L162)
		* *otherwise*
			* [check\_object\_size](https://github.com/torvalds/linux/blob/7ad639840acf2800b5f387c495795f995a67a329/include/linux/thread_info.h#L202-L203)
* [copy\_to\_user](https://github.com/torvalds/linux/blob/a7a08b275a8bbade798c4bdaad07ade68fe7003c/include/linux/uaccess.h#L199)

## Symbol

* [EXPORT\_SYMBOL](https://github.com/torvalds/linux/blob/e1327a127703f94b8838d756cf6eaac506b329a7/include/linux/export.h#L163)
	* [\_EXPORT\_SYMBOL](https://github.com/torvalds/linux/blob/e1327a127703f94b8838d756cf6eaac506b329a7/include/linux/export.h#L160)
		* [\_\_EXPORT\_SYMBOL](https://github.com/torvalds/linux/blob/e1327a127703f94b8838d756cf6eaac506b329a7/include/linux/export.h#L137)
			* [\_\_cond\_export\_sym](https://github.com/torvalds/linux/blob/e1327a127703f94b8838d756cf6eaac506b329a7/include/linux/export.h#L139)
				* [\_\_\_cond\_export\_sym](https://github.com/torvalds/linux/blob/e1327a127703f94b8838d756cf6eaac506b329a7/include/linux/export.h#L141)
					* [\_\_cond\_export\_sym\_1](https://github.com/torvalds/linux/blob/e1327a127703f94b8838d756cf6eaac506b329a7/include/linux/export.h#L142)
						* [\_\_\_EXPORT\_SYMBOL](https://github.com/torvalds/linux/blob/e1327a127703f94b8838d756cf6eaac506b329a7/include/linux/export.h#L108)
							* [\_\_KSYMTAB\_ENTRY](https://github.com/torvalds/linux/blob/e1327a127703f94b8838d756cf6eaac506b329a7/include/linux/export.h#L50)
								* [RO\_DATA](https://github.com/torvalds/linux/blob/95faf6ba654dd334617f347023e65b06d791c4a6/include/asm-generic/vmlinux.lds.h#L484-L489)
* [kernel\_symbol\_value](https://github.com/torvalds/linux/blob/67d6212afda218d564890d1674bab28e8612170f/kernel/module.c#L465)
	* [offset\_to\_ptr](https://github.com/torvalds/linux/blob/bfb1a7c91fb7758273b4a8d735313d9cc388b502/include/linux/compiler.h#L241)

## Snippet

* gain root privileges
	* (kernel) `commit_creds(prepare_kernel_cred(NULL));`
* break out of namespaces
	* (kernel) `switch_task_namespaces(find_task_by_vpid(1), init_nsproxy);`
	* (user) `setns(open("/proc/1/ns/mnt", O_RDONLY), 0);`
	* (user) `setns(open("/proc/1/ns/pid", O_RDONLY), 0);`
	* (user) `setns(open("/proc/1/ns/net", O_RDONLY), 0);`


## Structures

| structure        | size          | flag (v5.14+)      | memo                      |
| ---------------- | ------------- | ------------------ | ------------------------- |
| ldt\_struct      | 16            | GFP_KERNEL_ACCOUNT |                           |
| shm\_file\_data  | 32            | GFP_KERNEL         |                           |
| seq\_operations  | 32            | GFP_KERNEL_ACCOUNT | /proc/self/stat           |
| msg\_msg         | 48 ~ 4096     | GFP_KERNEL_ACCOUNT |                           |
| msg\_msgseg      | 8 ~ 4096      | GFP_KERNEL_ACCOUNT |                           |
| subprocess\_info | 96            | GFP_KERNEL         | `socket(22, AF_INET, 0);` |
| timerfd\_ctx     | 216           | GFP_KERNEL         |                           |
| pipe\_buffer     | 640 = 40 x 16 | GFP_KERNEL_ACCOUNT |                           |
| tty\_struct      | 696           | GFP_KERNEL         | /dev/ptmx                 |
| setxattr         | 0 ~           | GFP_KERNEL         |                           |
| sk\_buff         | 320 ~         | GFP_KERNEL_ACCOUNT |                           |

### [ldt\_struct](https://github.com/torvalds/linux/blob/157807123c94acc8dcddd08a2335bd0173c5d68d/arch/x86/include/asm/mmu_context.h#L36)

* [modify\_ldt](https://github.com/torvalds/linux/blob/ec403e2ae0dfc85996aad6e944a98a16e6dfcc6d/arch/x86/kernel/ldt.c#L665-L666)
	* [write\_ldt](https://github.com/torvalds/linux/blob/ec403e2ae0dfc85996aad6e944a98a16e6dfcc6d/arch/x86/kernel/ldt.c#L625)
		* `#define LDT_ENTRIES 8192`
		* `#define LDT_ENTRY_SIZE 8`
		* [alloc\_ldt\_struct](https://github.com/torvalds/linux/blob/ec403e2ae0dfc85996aad6e944a98a16e6dfcc6d/arch/x86/kernel/ldt.c#L157)
	* [read\_ldt](https://github.com/torvalds/linux/blob/ec403e2ae0dfc85996aad6e944a98a16e6dfcc6d/arch/x86/kernel/ldt.c#L520-L523)
		* [desc\_struct](https://github.com/torvalds/linux/blob/097ee5b778b8970e1c2ed3ca1631b297d90acd61/arch/x86/include/asm/desc_defs.h#L16)
		* `copy_to_user`
			* `copy_to_user` won't panic the kernel when accessing wrong address

### [shm\_file\_data](https://github.com/torvalds/linux/blob/85b6d24646e4125c591639841169baa98a2da503/ipc/shm.c#L83)

* [shmat](https://github.com/torvalds/linux/blob/85b6d24646e4125c591639841169baa98a2da503/ipc/shm.c#L1685)
	* [do\_shmat](https://github.com/torvalds/linux/blob/85b6d24646e4125c591639841169baa98a2da503/ipc/shm.c#L1608)

### [seq_operations](https://github.com/torvalds/linux/blob/359745d78351c6f5442435f81549f0207ece28aa/include/linux/seq_file.h#L32)

* [proc\_stat\_init](https://github.com/torvalds/linux/blob/a130e8fbc7de796eb6e680724d87f4737a26d0ac/fs/proc/stat.c#L239)
	* [stat\_proc\_ops](https://github.com/torvalds/linux/blob/a130e8fbc7de796eb6e680724d87f4737a26d0ac/fs/proc/stat.c#L229-L235)
* [stat\_open](https://github.com/torvalds/linux/blob/a130e8fbc7de796eb6e680724d87f4737a26d0ac/fs/proc/stat.c#L226)
	* [single\_open\_size](https://github.com/torvalds/linux/blob/372904c080be44629d84bb15ed5e12eed44b5f9f/fs/seq_file.c#L600)
		* [single\_open](https://github.com/torvalds/linux/blob/372904c080be44629d84bb15ed5e12eed44b5f9f/fs/seq_file.c#L575)
			* `start = single_start`
			* `next = single_next`
			* `stop = single_stop`
			* `show = show`
* [seq\_read\_iter](https://github.com/torvalds/linux/blob/372904c080be44629d84bb15ed5e12eed44b5f9f/fs/seq_file.c#L225)
	* `m->op->start`

### [msg\_msg](https://github.com/torvalds/linux/blob/34b56df922b10ac2876f268c522951785bf333fd/include/linux/msg.h#L9), [msg\_msgseg](https://github.com/torvalds/linux/blob/137ec390fad41928307216ea9f91acf5cf6f4204/ipc/msgutil.c#L37)

* [msg\_queue](https://github.com/torvalds/linux/blob/18319498fdd4cdf8c1c2c48cd432863b1f915d6f/ipc/msg.c#L59)
	* `q_messages` &rarr; `msg_msg`
* [msgsnd](https://github.com/torvalds/linux/blob/18319498fdd4cdf8c1c2c48cd432863b1f915d6f/ipc/msg.c#L968)
	* [ksys\_msgsnd](https://github.com/torvalds/linux/blob/18319498fdd4cdf8c1c2c48cd432863b1f915d6f/ipc/msg.c#L962)
		* [do\_msgsnd](https://github.com/torvalds/linux/blob/18319498fdd4cdf8c1c2c48cd432863b1f915d6f/ipc/msg.c#L858)
			* [load\_msg](https://github.com/torvalds/linux/blob/137ec390fad41928307216ea9f91acf5cf6f4204/ipc/msgutil.c#L91)
				* [alloc\_msg](https://github.com/torvalds/linux/blob/137ec390fad41928307216ea9f91acf5cf6f4204/ipc/msgutil.c#L52-L75)
* [msgrcv](https://github.com/torvalds/linux/blob/18319498fdd4cdf8c1c2c48cd432863b1f915d6f/ipc/msg.c#L1267)
	* [ksys\_msgrcv](https://github.com/torvalds/linux/blob/18319498fdd4cdf8c1c2c48cd432863b1f915d6f/ipc/msg.c#L1261)
		* [do\_msgrcv](https://github.com/torvalds/linux/blob/18319498fdd4cdf8c1c2c48cd432863b1f915d6f/ipc/msg.c#L1152-L1155)
			* `#define MSG_COPY 040000`

### [subprocess\_info](https://github.com/torvalds/linux/blob/55e6074e3fa67e1fb9ec140904db7e6cae6eda4b/include/linux/umh.h#L19)

* [socket](https://github.com/torvalds/linux/blob/0fc95dec096c2133942c382396172ae4487b4d57/net/socket.c#L1570)
	* [\_\_sys\_socket](https://github.com/torvalds/linux/blob/0fc95dec096c2133942c382396172ae4487b4d57/net/socket.c#L1561)
		* [sock\_create](https://github.com/torvalds/linux/blob/0fc95dec096c2133942c382396172ae4487b4d57/net/socket.c#L1519)
			* [\_\_sock\_create](https://github.com/torvalds/linux/blob/0fc95dec096c2133942c382396172ae4487b4d57/net/socket.c#L1449)
				* [\_\_request\_module](https://github.com/torvalds/linux/blob/17652f4240f7a501ecc13e9fdb06982569cde51f/kernel/kmod.c#L170)
					* [call\_modprobe](https://github.com/torvalds/linux/blob/17652f4240f7a501ecc13e9fdb06982569cde51f/kernel/kmod.c#L93)
						* [call\_usermodehelper\_setup](https://github.com/torvalds/linux/blob/48207f7d41c8bdae94d2aae11620ed76fee95d45/kernel/umh.c#L365)

### [timerfd\_ctx](https://github.com/torvalds/linux/blob/66f7b0c8aadd2785fc29f2c71477ebc16f4e38cc/fs/timerfd.c#L31)

* [timerfd\_create](https://github.com/torvalds/linux/blob/66f7b0c8aadd2785fc29f2c71477ebc16f4e38cc/fs/timerfd.c#L428)
* [timerfd\_release](https://github.com/torvalds/linux/blob/66f7b0c8aadd2785fc29f2c71477ebc16f4e38cc/fs/timerfd.c#L245)
	* `kfree_rcu`

### [pipe\_buffer](https://github.com/torvalds/linux/blob/1998f19324d24df7de4e74d81503b4299eb99e7d/include/linux/pipe_fs_i.h#L26)

* [pipe](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L1033), [pipe2](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L1028)
	* [do\_pipe2](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L1010)
		* [do\_pipe\_flags](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L962)
			* [create\_pipe\_files](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L913)
				* [get\_pipe\_inode](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L881-L888)
					* [alloc\_pipe\_info](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L785-L808)
						* `#define PIPE_DEF_BUFFERS 16`
				* [pipefifo\_fops](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L1218)
* [pipe\_write](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L522-L525)
	* `buf->ops = &anon_pipe_buf_ops;`
* [pipe\_release](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L734)
	* [put\_pipe\_info](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L711)
		* [free\_pipe\_info](https://github.com/torvalds/linux/blob/2ed147f015af2b48f41c6f0b6746aa9ea85c19f3/fs/pipe.c#L844)
			* [pipe\_buf\_release](https://github.com/torvalds/linux/blob/1998f19324d24df7de4e74d81503b4299eb99e7d/include/linux/pipe_fs_i.h#L203)
				* `ops->release`

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

### setxattr

* [setxattr](https://github.com/torvalds/linux/blob/6961fed420146297467efe4bc022458818839a1a/fs/xattr.c#L607)
	* [path\_setxattr](https://github.com/torvalds/linux/blob/6961fed420146297467efe4bc022458818839a1a/fs/xattr.c#L595-L596)
		* [setxattr](https://github.com/torvalds/linux/blob/6961fed420146297467efe4bc022458818839a1a/fs/xattr.c#L563-L577)
			* `vfs_setxattr` may fail, but `kvmalloc` and `kvfree` complete successfully

### [sk\_buff](https://github.com/torvalds/linux/blob/364df53c081d93fcfd6b91085ff2650c7f17b3c7/include/linux/skbuff.h#L946-L949)

* [socketpair](https://github.com/torvalds/linux/blob/0fc95dec096c2133942c382396172ae4487b4d57/net/socket.c#L1672)
	* [\_\_sys\_socketpair](https://github.com/torvalds/linux/blob/0fc95dec096c2133942c382396172ae4487b4d57/net/socket.c#L1619-L1626)
		* [sock\_create](https://github.com/torvalds/linux/blob/0fc95dec096c2133942c382396172ae4487b4d57/net/socket.c#L1519)
			* [\_\_sock\_create](https://github.com/torvalds/linux/blob/0fc95dec096c2133942c382396172ae4487b4d57/net/socket.c#L1453-L1470)
				* *case PF\_UNIX*
					* [unix\_family\_ops](https://github.com/torvalds/linux/blob/b6459415b384cb829f0b2a4268f211c789f6cf0b/net/unix/af_unix.c#L3409-L3410)
						* [unix\_create](https://github.com/torvalds/linux/blob/b6459415b384cb829f0b2a4268f211c789f6cf0b/net/unix/af_unix.c#L944)
							* *case SOCK\_DGRAM*
								* [unix\_dgram\_ops](https://github.com/torvalds/linux/blob/b6459415b384cb829f0b2a4268f211c789f6cf0b/net/unix/af_unix.c#L809)
							* [unix_create1](https://github.com/torvalds/linux/blob/b6459415b384cb829f0b2a4268f211c789f6cf0b/net/unix/af_unix.c#L918)
								* `sk->sk_allocation	= GFP_KERNEL_ACCOUNT;`
* [unix\_dgram\_sendmsg](https://github.com/torvalds/linux/blob/b6459415b384cb829f0b2a4268f211c789f6cf0b/net/unix/af_unix.c#L1896-L1898)
	* [sock\_alloc\_send\_pskb](https://github.com/torvalds/linux/blob/a1cdec57e03a1352e92fbbe7974039dda4efcec0/net/core/sock.c#L2586-L2587)
		* [alloc\_skb\_with\_frags](https://github.com/torvalds/linux/blob/224102de2ff105a2c05695e66a08f4b5b6b2d19c/net/core/skbuff.c#L5956)
			* [alloc\_skb](https://github.com/torvalds/linux/blob/364df53c081d93fcfd6b91085ff2650c7f17b3c7/include/linux/skbuff.h#L1158)
				* [\_\_alloc\_skb](https://github.com/torvalds/linux/blob/224102de2ff105a2c05695e66a08f4b5b6b2d19c/net/core/skbuff.c#L424-L426)
					* `struct skb_shared_info` is at the end of `data`

## Variables

| variable       | memo                            |
| -------------- | ------------------------------- |
| modprobe\_path | /proc/sys/kernel/modprobe       |
| core\_pattern  | /proc/sys/kernel/core_pattern   |
| n\_tty\_ops    | (read) `scanf`, (ioctl) `fgets` |

### [modprobe\_path](https://github.com/torvalds/linux/blob/17652f4240f7a501ecc13e9fdb06982569cde51f/kernel/kmod.c#L61)

* [execve](https://github.com/torvalds/linux/blob/f0bc21b268c1464603192a00851cdbbf7c2cdc36/fs/exec.c#L2070)
	* [do\_execve](https://github.com/torvalds/linux/blob/f0bc21b268c1464603192a00851cdbbf7c2cdc36/fs/exec.c#L1994)
		* [do\_execveat\_common](https://github.com/torvalds/linux/blob/f0bc21b268c1464603192a00851cdbbf7c2cdc36/fs/exec.c#L1926)
			* [bprm\_execve](https://github.com/torvalds/linux/blob/f0bc21b268c1464603192a00851cdbbf7c2cdc36/fs/exec.c#L1837)
				* [exec\_binprm](https://github.com/torvalds/linux/blob/f0bc21b268c1464603192a00851cdbbf7c2cdc36/fs/exec.c#L1768)
					* [search\_binary\_handler](https://github.com/torvalds/linux/blob/f0bc21b268c1464603192a00851cdbbf7c2cdc36/fs/exec.c#L1739-L1743)
						* [\_\_request\_module](https://github.com/torvalds/linux/blob/17652f4240f7a501ecc13e9fdb06982569cde51f/kernel/kmod.c#L170)
							* [call\_modprobe](https://github.com/torvalds/linux/blob/17652f4240f7a501ecc13e9fdb06982569cde51f/kernel/kmod.c#L93-L98)
								* [call\_usermodehelper\_setup](https://github.com/torvalds/linux/blob/48207f7d41c8bdae94d2aae11620ed76fee95d45/kernel/umh.c#L358)
								* [call\_usermodehelper\_exec](https://github.com/torvalds/linux/blob/48207f7d41c8bdae94d2aae11620ed76fee95d45/kernel/umh.c#L404)

### [core\_pattern](https://github.com/torvalds/linux/blob/f0bc21b268c1464603192a00851cdbbf7c2cdc36/fs/coredump.c#L58)

* [do\_coredump](https://github.com/torvalds/linux/blob/f0bc21b268c1464603192a00851cdbbf7c2cdc36/fs/coredump.c#L565-L628)
	* [format\_corename](https://github.com/torvalds/linux/blob/f0bc21b268c1464603192a00851cdbbf7c2cdc36/fs/coredump.c#L199)
	* [call\_usermodehelper\_setup](https://github.com/torvalds/linux/blob/48207f7d41c8bdae94d2aae11620ed76fee95d45/kernel/umh.c#L358)
	* [call\_usermodehelper\_exec](https://github.com/torvalds/linux/blob/48207f7d41c8bdae94d2aae11620ed76fee95d45/kernel/umh.c#L404)

### [poweroff\_cmd](https://github.com/torvalds/linux/blob/f78e9de80f5ad15719a069a4e6c11e2777122188/kernel/reboot.c#L420)

* [orderly\_poweroff](https://github.com/torvalds/linux/blob/f78e9de80f5ad15719a069a4e6c11e2777122188/kernel/reboot.c#L499)
	* [poweroff\_work\_func](https://github.com/torvalds/linux/blob/f78e9de80f5ad15719a069a4e6c11e2777122188/kernel/reboot.c#L483)
		* [\_\_orderly\_poweroff](https://github.com/torvalds/linux/blob/f78e9de80f5ad15719a069a4e6c11e2777122188/kernel/reboot.c#L462)
			* [run\_cmd](https://github.com/torvalds/linux/blob/f78e9de80f5ad15719a069a4e6c11e2777122188/kernel/reboot.c#L434)
				* [call\_usermodehelper](https://github.com/torvalds/linux/blob/48207f7d41c8bdae94d2aae11620ed76fee95d45/kernel/umh.c#L479-L484)
					* [call\_usermodehelper\_setup](https://github.com/torvalds/linux/blob/48207f7d41c8bdae94d2aae11620ed76fee95d45/kernel/umh.c#L358)
					* [call\_usermodehelper\_exec](https://github.com/torvalds/linux/blob/48207f7d41c8bdae94d2aae11620ed76fee95d45/kernel/umh.c#L404)

### [n\_tty\_ops](https://github.com/torvalds/linux/blob/3593030761630e09200072a4bd06468892c27be3/drivers/tty/n_tty.c#L2392)

* [tty\_struct](https://github.com/torvalds/linux/blob/4072254f96f954ec0d34899f15d987803b6d76a2/include/linux/tty.h#L204)
	* [tty\_ldisc](https://github.com/torvalds/linux/blob/40f4268cddb93d17a11579920d940c2dca8b9445/include/linux/tty_ldisc.h#L237)
* [n\_tty\_init](https://github.com/torvalds/linux/blob/3593030761630e09200072a4bd06468892c27be3/drivers/tty/n_tty.c#L2418)
	* [tty\_register\_ldisc](https://github.com/torvalds/linux/blob/cbb68f91995001c79a9b89dcf6a25d22c7b92872/drivers/tty/tty_ldisc.c#L67)

