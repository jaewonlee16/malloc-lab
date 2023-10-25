/*
 * mm.c - malloc implementation using LIFO explicit free lists.
 * Each block consists or 4byte header and 4 byte footer.
 * Free blocks have additional block that points to the next and previous free block.
 * Therefore, the minimum block size is 4 + 4 + 4 + 4 = 16.
 * It uses best fit search, such that if the free size is same as the malloc size it finds it.
 * Other than that, it finds the minimum free size that the 
 * remainder of free block can be splitted (bigger than MIN_BLK_SIZE).
 * Coalescing is done every time after heap extension, free, and splitting called by malloc or realloc.
 * Heap extension is implemented by not just extending the requested size.
 * It looks if previous block is free and merge with it.
 * The total score is 52 (util) + 40 (throughput) = 92 / 100.
 *
 * jaewonlee16
 *
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
#define CHUNKSIZE (1<<12)
#define OVERHEAD 8
#define MIN_BLK_SIZE 16

#define MAX(x, y) ((x) > (y) ? (x) : (y)) 
#define MIN(x, y) ((x) < (y) ? (x) : (y))

#define GET_VAL_AT_PTR(p)            (*(size_t *)(p))
#define PUT_VAL_AT_PTR(p, val)       (*(size_t *)(p) = (val))

#define CONCAT_SIZE_ALLOC(size, alloc) ((size) | (alloc))
#define GET_SIZE(p)  (GET_VAL_AT_PTR(p) & ~0x7)
#define GET_ALLOC(p) (GET_VAL_AT_PTR(p) & 0x1)

#define HEADER_OF_BP(ptr) ((char *)(ptr) - WORDSIZE)
#define FOOTER_OF_BP(ptr) ((char *)(ptr) + GET_SIZE(HEADER_OF_BP(ptr)) - DWORDSIZE)
#define FOOTER_OF_PREV_BP(ptr) ((char *)(ptr) - DWORDSIZE)


#define NEXT_BLK_PTR(ptr) ((char *)(ptr) + GET_SIZE((char *)(ptr) - WORDSIZE))
#define PREV_BLK_PTR(ptr) ((char *)(ptr) - GET_SIZE((char *)(ptr) - DWORDSIZE))

#define NEXT_FREE(bp) (*(void **)(bp))
#define PREV_FREE(bp) (*(void **)(bp + WORDSIZE))

static void* free_list_ptr = NULL;
static unsigned int min_free_size = 99999999;
static unsigned int real_best_min_free_size = 99999999;

/* functions */
static void* find_first_fit(size_t adjusted_size);
static void* find_best_fit(size_t adjusted_size);
static void place_and_split_free_blk(void* bp, size_t adjusted_size, size_t free_size);
static void place_requested_blk(void* bp, size_t adjusted_size);
static void* coalesce_free_blk(void* bp);
static void* extend_heap(size_t words);


static void remove_free_from_explicit_list(void* bp){
	void* next = NEXT_FREE(bp);
	void* prev = PREV_FREE(bp);

	if (next == NULL && prev == NULL){
		free_list_ptr = NULL;	// there is no more free block anymore!
	}
	else if (next != NULL && prev == NULL){
		PREV_FREE(next) = NULL;
		free_list_ptr = next;
	}
	else if (next == NULL && prev != NULL){
		NEXT_FREE(prev) = NULL;
	}
	else /* if (next == NULL && prev == NULL) */{
		NEXT_FREE(prev) = next;
		PREV_FREE(next) = prev;
	}
}

static void add_bp_to_free_list(void* bp){ // LIFO
	if (free_list_ptr == NULL){
		free_list_ptr = bp;
		NEXT_FREE(bp) = NULL;
		PREV_FREE(bp) = NULL;
	}
	else{
		NEXT_FREE(bp) = free_list_ptr;
  		PREV_FREE(free_list_ptr) = bp;
  		PREV_FREE(bp) = NULL;
  		free_list_ptr = bp;
	}
}

/* Not used here. Used best fit below. */
static void* find_first_fit(size_t adjusted_size){
	void* bp;
	for (bp = free_list_ptr; bp != NULL; bp = NEXT_FREE(bp)){
		if (GET_SIZE(HEADER_OF_BP(bp)) >= adjusted_size)
			return bp;
	}
	return NULL;
}

/* best fit search.
 * Immediately returns if free block size is same as requested size.
 * Finds the free block that has the minimum size, which is second_best_result.
 * The real best_result is free block that can be splitted. */
static void* find_best_fit(size_t adjusted_size){
	void* bp;
	void* best_result = NULL;
	void* second_best_result = NULL;
	size_t bp_size;
	for (bp = free_list_ptr; bp != NULL; bp = NEXT_FREE(bp)){
		if((bp_size = GET_SIZE(HEADER_OF_BP(bp))) == adjusted_size){
			best_result = bp;
			break;
		}
		if (bp_size > adjusted_size && bp_size < min_free_size){
			min_free_size = bp_size;
			second_best_result = bp;
		}
		if (bp_size >= (adjusted_size + MIN_BLK_SIZE) && bp_size < real_best_min_free_size){ // because free space can be splitted
			real_best_min_free_size = bp_size;
			best_result = bp;
		}
		
	}
	min_free_size = 99999999;
	real_best_min_free_size = 99999999;
	if (best_result != NULL)
		return best_result;
	return second_best_result;
	
}

static void place_and_split_free_blk(void* bp, size_t adjusted_size, size_t free_size){
	PUT_VAL_AT_PTR(HEADER_OF_BP(bp), CONCAT_SIZE_ALLOC(adjusted_size, 1));
	PUT_VAL_AT_PTR(FOOTER_OF_BP(bp), CONCAT_SIZE_ALLOC(adjusted_size, 1));
	remove_free_from_explicit_list(bp);

	bp = NEXT_BLK_PTR(bp);
	PUT_VAL_AT_PTR(HEADER_OF_BP(bp), CONCAT_SIZE_ALLOC(free_size - adjusted_size, 0));
	PUT_VAL_AT_PTR(FOOTER_OF_BP(bp), CONCAT_SIZE_ALLOC(free_size - adjusted_size, 0));
	coalesce_free_blk(bp);
}

static void place_requested_blk(void* bp, size_t adjusted_size){
	size_t free_size = GET_SIZE(HEADER_OF_BP(bp));
	if ((free_size - adjusted_size) >= MIN_BLK_SIZE){
		place_and_split_free_blk(bp, adjusted_size, free_size);
	}
	else{
		PUT_VAL_AT_PTR(HEADER_OF_BP(bp), CONCAT_SIZE_ALLOC(free_size, 1));
		PUT_VAL_AT_PTR(FOOTER_OF_BP(bp), CONCAT_SIZE_ALLOC(free_size, 1));
		remove_free_from_explicit_list(bp);
	}
}


static void* coalesce_free_blk(void* bp){
    size_t prev_alloc = GET_ALLOC(FOOTER_OF_PREV_BP(bp)); 
    size_t next_alloc = GET_ALLOC(HEADER_OF_BP(NEXT_BLK_PTR(bp))); 
    size_t size =  GET_SIZE(HEADER_OF_BP(bp));

    if (prev_alloc && !next_alloc){ // case2 
        size += GET_SIZE(HEADER_OF_BP(NEXT_BLK_PTR(bp))); 
	remove_free_from_explicit_list(NEXT_BLK_PTR(bp));
        PUT_VAL_AT_PTR(HEADER_OF_BP(bp),CONCAT_SIZE_ALLOC(size,0));
        PUT_VAL_AT_PTR(FOOTER_OF_BP(bp), CONCAT_SIZE_ALLOC(size,0)); 
    }
    else if(!prev_alloc && next_alloc){ // case 3  
        size+= GET_SIZE(FOOTER_OF_PREV_BP(bp)); 
        PUT_VAL_AT_PTR(FOOTER_OF_BP(bp), CONCAT_SIZE_ALLOC(size,0)); 
        bp = PREV_BLK_PTR(bp); 
        PUT_VAL_AT_PTR(HEADER_OF_BP(bp), CONCAT_SIZE_ALLOC(size,0)); 
	remove_free_from_explicit_list(bp);
    }
    else if (!prev_alloc && !next_alloc){ // case 4
        size+= GET_SIZE(FOOTER_OF_PREV_BP(bp)) + GET_SIZE(FOOTER_OF_BP(NEXT_BLK_PTR(bp))); 
	remove_free_from_explicit_list(PREV_BLK_PTR(bp));
	remove_free_from_explicit_list(NEXT_BLK_PTR(bp));
        PUT_VAL_AT_PTR(HEADER_OF_BP(PREV_BLK_PTR(bp)), CONCAT_SIZE_ALLOC(size,0));
        PUT_VAL_AT_PTR(FOOTER_OF_BP(NEXT_BLK_PTR(bp)), CONCAT_SIZE_ALLOC(size,0)); 
        bp = PREV_BLK_PTR(bp);
    }
    
    add_bp_to_free_list(bp);

    return bp;
}
static void* extend_heap(size_t size){
	char* bp;
	void* footer_prev = mem_heap_hi() - 0x7;
	size_t prev_blk_size = GET_SIZE(footer_prev);
	char * prev = (char*)footer_prev + DWORDSIZE - prev_blk_size;
	if (!GET_ALLOC(footer_prev) && size > prev_blk_size){ //merge with previous free block
		mem_sbrk(size - prev_blk_size);
		remove_free_from_explicit_list(prev);
		bp = prev;
	}


	else if ((bp = mem_sbrk(size)) == NULL){
		printf("why???????????");
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
    static void* heap_list_ptr = NULL;

    if((heap_list_ptr = mem_sbrk(6*WORDSIZE)) == NULL){
	    printf("why");
	    return -1;
    }
    PUT_VAL_AT_PTR(heap_list_ptr, CONCAT_SIZE_ALLOC(OVERHEAD, 1)); // prologue header
    PUT_VAL_AT_PTR(heap_list_ptr + WORDSIZE, CONCAT_SIZE_ALLOC(MIN_BLK_SIZE, 0)); // blk header
    PUT_VAL_AT_PTR(heap_list_ptr + 2*WORDSIZE, 0); // NEXT: NULL
    PUT_VAL_AT_PTR(heap_list_ptr + 3*WORDSIZE, 0); // PREV: NULL
    PUT_VAL_AT_PTR(heap_list_ptr + 4*WORDSIZE, CONCAT_SIZE_ALLOC(MIN_BLK_SIZE, 0)); // blk footer
    PUT_VAL_AT_PTR(heap_list_ptr + 5*WORDSIZE, CONCAT_SIZE_ALLOC(0, 1)); // epilogue footer

    free_list_ptr = heap_list_ptr + 2*WORDSIZE;
    return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
	size_t adjusted_blk_size;
	size_t extendsize;
	char* bp;

	adjusted_blk_size = ALIGN(size + OVERHEAD);

	if ((bp = find_best_fit(adjusted_blk_size)) != NULL){
		place_requested_blk(bp, adjusted_blk_size);
		return bp;
	}

	extendsize = MAX(adjusted_blk_size, CHUNKSIZE);
	if ((bp = extend_heap(extendsize)) == NULL)
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
 * mm_realloc - Implemented by dividing in to cases.
 * If the requested size is smaller, it uses the same pointer.
 * If the requested size is bigger and next block is free block,
 * it uses the same pointer and merges with the next free block.
 * Both of cases considered free block splitting.
 * Other than those cases, it is implemented by simply using mm_malloc and mm_free.
 */
void *mm_realloc(void *oldptr, size_t size)
{
	void *newptr;
	size_t old_size = GET_SIZE(HEADER_OF_BP(oldptr));
	size_t adjusted_blk_size = ALIGN(size + OVERHEAD);
	size_t merged_size = old_size + GET_SIZE(HEADER_OF_BP(NEXT_BLK_PTR(oldptr)));
	void* bp;
	if (adjusted_blk_size == old_size)
		return oldptr;
	else if (adjusted_blk_size < old_size && (old_size - adjusted_blk_size) >= MIN_BLK_SIZE){
		PUT_VAL_AT_PTR(HEADER_OF_BP(oldptr), CONCAT_SIZE_ALLOC(adjusted_blk_size, 1));
		PUT_VAL_AT_PTR(FOOTER_OF_BP(oldptr), CONCAT_SIZE_ALLOC(adjusted_blk_size, 1));

		bp = NEXT_BLK_PTR(oldptr);
		PUT_VAL_AT_PTR(HEADER_OF_BP(bp), CONCAT_SIZE_ALLOC(old_size - adjusted_blk_size, 0));
		PUT_VAL_AT_PTR(FOOTER_OF_BP(bp), CONCAT_SIZE_ALLOC(old_size - adjusted_blk_size, 0));
		coalesce_free_blk(bp);
		return oldptr;
    	}
	else if (adjusted_blk_size > old_size && !GET_ALLOC(HEADER_OF_BP(NEXT_BLK_PTR(oldptr))) 
			&& merged_size >= adjusted_blk_size + MIN_BLK_SIZE){
		remove_free_from_explicit_list(NEXT_BLK_PTR(oldptr));
      		PUT_VAL_AT_PTR(HEADER_OF_BP(oldptr), CONCAT_SIZE_ALLOC(adjusted_blk_size, 1));
      		PUT_VAL_AT_PTR(FOOTER_OF_BP(oldptr), CONCAT_SIZE_ALLOC(adjusted_blk_size, 1));
      		bp = NEXT_BLK_PTR(oldptr);
      		PUT_VAL_AT_PTR(HEADER_OF_BP(bp), CONCAT_SIZE_ALLOC(merged_size - adjusted_blk_size, 1));
      		PUT_VAL_AT_PTR(FOOTER_OF_BP(bp), CONCAT_SIZE_ALLOC(merged_size - adjusted_blk_size, 1));
      		mm_free(bp);
      		return oldptr;
	}

    	newptr = mm_malloc(size);
    	if (newptr == NULL)
      		return NULL;
    	memcpy(newptr, oldptr,MIN( old_size,size));
    	mm_free(oldptr);
    	return newptr;
}

