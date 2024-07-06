# Malloc Lab (CS:APP)
SNU ECE System Programming (430.658.004) : Fall 2023

### Final Score: 92 / 100
## Introduction
A dynamic storage allocator for C programs, i.e., your own version of `malloc` and `free`. 
You are encouraged to explore the design space creatively and implement an allocator that is correct, efficient, and fast.

## Hand Out Instructions
First, clone this repository

This will unpack several files into the directory. The only file you will be modifying and handing in is `mm.c`. 
The `mdriver.c` program is a driver program that allows you to evaluate the performance of your solution. 
Use the command `make` to generate the driver code and run it with the command:
```sh
./mdriver -V
```
(The `-V` flag displays helpful summary information.) When you have completed the lab, you will hand in only one file (`mm.c`), which contains your solution.

## How to Work on the Lab
Your dynamic storage allocator will consist of the following four functions, which are declared in `mm.h` and defined in `mm.c`:
- `int mm_init(void);`
- `void *mm_malloc(size_t size);`
- `void mm_free(void *ptr);`
- `void *mm_realloc(void *ptr, size_t size);`

The `mm.c` file provided implements the simplest, but still functionally correct, malloc package. 
Modify these functions (and possibly define other private static functions) to ensure they obey the following semantics:
- **`mm_init`**: Initializes the allocator.
- **`mm_malloc`**: Allocates a block of at least `size` bytes.
- **`mm_free`**: Frees a previously allocated block.
- **`mm_realloc`**: Changes the size of a previously allocated block.

## Heap Consistency Checker
Dynamic memory allocators are difficult to program correctly and efficiently. 
It is helpful to write a heap checker that scans the heap and checks it for consistency. 
Your heap checker will consist of the function `int mm_check(void)` in `mm.c`. 
It will check any invariants or consistency conditions you consider prudent. 
Style points will be given for your `mm_check` function. 
Make sure to put in comments and document what you are checking.

## Support Routines
The `memlib.c` package simulates the memory system for your dynamic memory allocator. You can invoke the following functions in `memlib.c`:
- `void *mem_sbrk(int incr);`
- `void *mem_heap_lo(void);`
- `void *mem_heap_hi(void);`
- `size_t mem_heapsize(void);`
- `size_t mem_pagesize(void);`

## The Trace-driven Driver Program
The driver program `mdriver.c` tests your `mm.c` package for correctness, space utilization, and throughput. 
The driver program is controlled by a set of trace files that are included in the `malloclab-handout.tar` distribution. 
Each trace file contains a sequence of allocate, reallocate, and free directions that instruct the driver to call your `mm_malloc`, `mm_realloc`, and `mm_free` routines in some sequence. 
The driver accepts the following command line arguments:
- `-t <tracedir>`
- `-f <tracefile>`
- `-h`
- `-l`
- `-v`
- `-V`

