# Heap Cheat Sheet

## Transition
![heap_trans](./heap_trans.jpg)

| symbol       | description                 |
| ------------ | --------------------------- |
| arrow        | malloc                      |
| dotted arrow | free                        |
| red arrow    | weak path                   |
| c            | (for\|back)word consolidate |
| m            | malloc consolidate          |
| s            | split the chunk             |
| 0 ~ 4        | priority (0: high, 4: low)  |

| path                   | method | description                                                    |
| ---------------------- | ------ | -------------------------------------------------------------- |
| fast &rarr; malloc     | malloc | 1st chunk in fast bin when tcache is empty                     |
| fast &rarr; tcache     | malloc | 2nd ~ 8th chunks in fast bin when tcache is empty              |
| unsorted &rarr; tcache | malloc | 1st ~ 7th just-fit chunks in unsorted bin when tcache is empty |
| unsorted &rarr; malloc | malloc | 8th just-fit chunk in unsorted bin when tcache is empty        |
| small &rarr; malloc    | malloc | 1st chunk in small bin when tcache is empty                    |
| small &rarr; tcache    | malloc | 2nd ~ 8th chunks in unsorted bin when tcache is empty          |

## Bins
|          | size         | type |
| -------- | ------------ | ---- |
| tcache   | 0x20 ~ 0x410 | FILO |
| fast     | 0x20 ~ 0x80  | FILO |
| unsorted | 0x20 ~       | FIFO |
| small    | 0x20 ~ 0x3f0 | FIFO |
| large    | 0x400 ~      | FIFO |

## Double Free
| 1st \ nth               | tcahe | fast | unsorted |
| ----------------------- | ----- | ---- | -------- |
| tcache                  | X     | X    | X        |
| fast                    | O     | O    | -        |
| unsorted [0x20 ~ 0x80]  | O     | O    | X        |
| unsorted [0x90 ~ 0x410] | O     | -    | X        |
| unsorted [0x420 ~]      | -     | -    | X        |
| small [0x20 ~ 0x80]     | O     | O    | X        |
| small [0x90 ~ 0x3f0]    | O     | -    | X        |
| large [0x400, 0x410]    | O     | -    | X        |
| large [0x420 ~]         | -     | -    | X        |

## Target
| variables                                        | trigger                                         | memo                       |
| ------------------------------------------------ | ----------------------------------------------- | -------------------------- |
| __malloc_hook                                    | malloc                                          |                            |
| __free_hook                                      | free                                            |                            |
| __realloc_hook                                   | realloc                                         |                            |
| __after_morecore_hook                            | sbrk                                            |                            |
| __malloc_initialize_hook                         | malloc (at initialization)                      |                            |
| __memalign_hook                                  | aligned_alloc, memalign, posix_memalign, valloc |                            |
| _dl_open_hook                                    | __libc_dlopen_mode, __libc_dlsym                |                            |
| (ld.so) _rtld_global._dl_ns[0]._ns_loaded        | _dl_fini                                        |                            |
| __printf_arginfo_table + __printf_function_table | printf                                          |                            |
| stderr + fs:[0x30]                               | _IO_file_XXX                                    | vtable == _IO_cookie_jumps |
| __exit_funcs + fs:[0x30]                         | exit                                            |                            |
| tls_dtor_list + fs:[0x30]                        | exit                                            |                            |

![terminate](./terminate.jpg)
