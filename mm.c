/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)


#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

/* MACROS from CS:APP chapter 9 */

#define WORDSIZE 4
#define DWORDSIZE 8
#define CHUNKSIZE (1<<5)
#define OVERHEAD 8

#define MAX(x, y) ((x) > (y) ? (x) : (y)) 
#define MIN(x, y) ((x) < (y) ? (x) : (y))

#define GET_VAL_AT_PTR(p)            (*(size_t *)(p))
#define PUT_VAL_AT_PTR(p, val)       (*(size_t *)(p) = (val))

#define CONCAT_SIZE_ALLOC(size, alloc) ((size) | (alloc))
#define GET_SIZE(p)  (GET_VAL_AT_PTR(p) & ~0x7)
#define GET_ALLOC(p) (GET_VAL_AT_PTR(p) & 0x1)

#define HEADER_OF_BP(ptr) ((char *)(ptr) - WORDSIZE)
#define FOOTER_OF_BP(ptr) ((char *)(ptr) + GET_SIZE(HEADER_OF_BP(ptr)) - DWORDSIZE)

#define NEXT_BLK_PTR(ptr) ((char *)(ptr) + GET_SIZE((char *)(ptr) - WORDSIZE))
#define PREV_BLK_PTR(ptr) ((char *)(ptr) - GET_SIZE((char *)(ptr) - DWORDSIZE))

static void* heap_list_ptr = NULL;

/* functions */
static void* find_first_fit(size_t adjusted_size);
static void place_and_split_free_blk(void* bp, size_t adjusted_size, size_t free_size);
static void place_requested_blk(void* bp, size_t adjusted_size);
static inline size_t allocate_even_number_for_allignment(size_t words);
static void* coalesce_free_blk(void* bp);
static void* extend_heap(size_t words);


static void* find_first_fit(size_t adjusted_size){
	void* bp;
	for (bp = heap_list_ptr; GET_SIZE(HEADER_OF_BP(bp)) > 0; bp = NEXT_BLK_PTR(bp)){
		size_t header = HEADER_OF_BP(bp);
		if (!GET_ALLOC(header) && (GET_SIZE(header) >= adjusted_size))
			return bp;
	}
	return NULL;
}

static void place_and_split_free_blk(void* bp, size_t adjusted_size, size_t free_size){
	PUT_VAL_AT_PTR(HEADER_OF_BP(bp), CONCAT_SIZE_ALLOC(adjusted_size, 1));
	PUT_VAL_AT_PTR(FOOTER_OF_BP(bp), CONCAT_SIZE_ALLOC(adjusted_size, 1));
	bp = NEXT_BLK_PTR(bp);
	PUT_VAL_AT_PTR(HEADER_OF_BP(bp), CONCAT_SIZE_ALLOC(free_size - adjusted_size, 0));
	PUT_VAL_AT_PTR(FOOTER_OF_BP(bp), CONCAT_SIZE_ALLOC(free_size - adjusted_size, 0));
}

static void place_requested_blk(void* bp, size_t adjusted_size){
	size_t free_size = GET_SIZE(HEADER_OF_BP(bp));
	if ((free_size - adjusted_size) >= (OVERHEAD + ALIGNMENT)){
		place_and_split_free_blk(bp, adjusted_size, free_size);
	}
	else{
		PUT_VAL_AT_PTR(HEADER_OF_BP(bp), CONCAT_SIZE_ALLOC(free_size, 1));
		PUT_VAL_AT_PTR(FOOTER_OF_BP(bp), CONCAT_SIZE_ALLOC(free_size, 1));
	}
}



static inline size_t allocate_even_number_for_allignment(size_t words){
	return (words % 2) ? (words + 1) * WORDSIZE : words * WORDSIZE;
}

static void* coalesce_free_blk(void* bp){
    size_t prev_alloc = GET_ALLOC(FOOTER_OF_BP(PREV_BLK_PTR(bp))); 
    size_t next_alloc = GET_ALLOC(HEADER_OF_BP(NEXT_BLK_PTR(bp))); 
    size_t size =  GET_SIZE(HEADER_OF_BP(bp));

    if (prev_alloc && next_alloc){ // case 1 
        return bp; 
    }
    else if (prev_alloc && !next_alloc){ // case2 
        size += GET_SIZE(HEADER_OF_BP(NEXT_BLK_PTR(bp))); 
        PUT_VAL_AT_PTR(HEADER_OF_BP(bp),CONCAT_SIZE_ALLOC(size,0));
        PUT_VAL_AT_PTR(FOOTER_OF_BP(bp), CONCAT_SIZE_ALLOC(size,0)); 
    }
    else if(!prev_alloc && next_alloc){ // case 3  
        size+= GET_SIZE(HEADER_OF_BP(PREV_BLK_PTR(bp))); 
        PUT_VAL_AT_PTR(FOOTER_OF_BP(bp), CONCAT_SIZE_ALLOC(size,0)); 
        PUT_VAL_AT_PTR(HEADER_OF_BP(PREV_BLK_PTR(bp)), CONCAT_SIZE_ALLOC(size,0)); 
        bp = PREV_BLK_PTR(bp); 
    }
    else { // case 4
        size+= GET_SIZE(HEADER_OF_BP(PREV_BLK_PTR(bp))) + GET_SIZE(FOOTER_OF_BP(NEXT_BLK_PTR(bp))); 
        PUT_VAL_AT_PTR(HEADER_OF_BP(PREV_BLK_PTR(bp)), CONCAT_SIZE_ALLOC(size,0));
        PUT_VAL_AT_PTR(FOOTER_OF_BP(NEXT_BLK_PTR(bp)), CONCAT_SIZE_ALLOC(size,0)); 
        bp = PREV_BLK_PTR(bp);
    }
    return bp;
}
static void* extend_heap(size_t words){
	char* bp;
	size_t size;

	size = allocate_even_number_for_allignment(words);

	if ((bp = mem_sbrk(size)) == NULL){
		return NULL;
	}

    	PUT_VAL_AT_PTR(HEADER_OF_BP(bp), CONCAT_SIZE_ALLOC(size, 0));
    	PUT_VAL_AT_PTR(FOOTER_OF_BP(bp), CONCAT_SIZE_ALLOC(size, 0));
    	PUT_VAL_AT_PTR(HEADER_OF_BP(NEXT_BLK_PTR(bp)), CONCAT_SIZE_ALLOC(0, 1));

	return coalesce_free_blk(bp);
}

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    if((heap_list_ptr = mem_sbrk(4*WORDSIZE)) == NULL){
	    return -1;
    }

    PUT_VAL_AT_PTR(heap_list_ptr, 0);
    PUT_VAL_AT_PTR(heap_list_ptr + WORDSIZE, CONCAT_SIZE_ALLOC(OVERHEAD, 1));
    PUT_VAL_AT_PTR(heap_list_ptr + DWORDSIZE, CONCAT_SIZE_ALLOC(OVERHEAD, 1));
    PUT_VAL_AT_PTR(heap_list_ptr + WORDSIZE + DWORDSIZE, CONCAT_SIZE_ALLOC(0, 1));
    heap_list_ptr += DWORDSIZE;

    if (extend_heap(CHUNKSIZE / WORDSIZE) == NULL){
	    printf("why??????");
    	return -1;
    }

    return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
	/*
    int newsize = ALIGN(size + SIZE_T_SIZE);
    void *p = mem_sbrk(newsize);
    if (p == (void *)-1)
	return NULL;
    else {
        *(size_t *)p = size;
        return (void *)((char *)p + SIZE_T_SIZE);
    }
    */
	size_t adjusted_blk_size;
	size_t extendsize;
	char* bp;

	if (size <= 0)
		return NULL;

	adjusted_blk_size = ALIGN(size + OVERHEAD);

	if ((bp = find_first_fit(adjusted_blk_size)) != NULL){
		place_requested_blk(bp, adjusted_blk_size);
		return bp;
	}

	extendsize = MAX(adjusted_blk_size, CHUNKSIZE);
	if ((bp = extend_heap(extendsize/WORDSIZE)) == NULL)
		return NULL;
	place_requested_blk(bp, adjusted_blk_size);
	return bp;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *bp)
{
	size_t size = GET_SIZE(HEADER_OF_BP(bp));

	PUT_VAL_AT_PTR(HEADER_OF_BP(bp), CONCAT_SIZE_ALLOC(size, 0));
	PUT_VAL_AT_PTR(FOOTER_OF_BP(bp), CONCAT_SIZE_ALLOC(size, 0));
	coalesce_free_blk(bp);
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *oldptr, size_t size)
{
    void *newptr;
    //size_t adjusted_size = ALIGN(size + OVERHEAD);
    size_t copySize = GET_SIZE(HEADER_OF_BP(oldptr));

    newptr = mm_malloc(size);
    if (newptr == NULL)
      return NULL;
    memcpy(newptr, oldptr,MIN( copySize,size));
    mm_free(oldptr);
    return newptr;
}














