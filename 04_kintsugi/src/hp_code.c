#include "hp_code.h"


struct __pack hp_code_node {
    struct hp_code_node *next;
    uint32_t size;
};

#define HP_CODE_NODE_SIZE   (sizeof(struct hp_code_node))
#define HP_CODE_MIN_ALLOC_SIZE (8)



// the list must be in the hotpatch code section because otherwise everyone can modify it
__attribute__((section(".hotpatch_code")))
__attribute__((used))
__attribute__((aligned(4)))
struct hp_code_node *hp_code_free_list = NULL;

// define the code region for the hotpatch code
#define HP_CODE_MEMORY_SIZE_ALIGNED (align_up(align_up(HP_CODE_MEMORY_SIZE + HP_SLOT_COUNT * sizeof(struct hp_code_node) + 2 + sizeof(void *), 8), 2))

__hotpatch_code
__attribute__((aligned(4)))
uint8_t hp_code_memory[HP_CODE_MEMORY_SIZE_ALIGNED] = { 0 };

void
__ramfunc
hp_code_init(void) {
    hp_code_free_list = (struct hp_code_node *)(hp_code_memory);
    hp_code_free_list->next = (struct hp_code_node*)NULL;
    hp_code_free_list->size = HP_CODE_MEMORY_SIZE_ALIGNED;
}


__ramfunc
void *hp_code_allocate(uint32_t size) {
    struct hp_code_node *current, *previous, *new_node;

    //size += 2;
    //size = align_up(size, 8);
    //size = align_up(size, 2);
    
    if (size == 0 || size > HP_CODE_MEMORY_SIZE_ALIGNED) {
        DEBUG_LOG("[error]: invalid size argument: %lu\r\n", size);
        return NULL; // Invalid size argument
    }

    current = hp_code_free_list;
    previous = NULL;

    // Find a suitable block
    while (current != NULL) {
        if (current->size >= size) {
            break;  
        }
        previous = current;
        current = current->next;
    }

    if (current == NULL) {
        DEBUG_LOG("[error]: no suitable block found\r\n");
        return NULL; // No suitable block found
    }

    // Check if we can split the block
    if (current->size >= size + HP_CODE_NODE_SIZE + HP_CODE_MIN_ALLOC_SIZE) {
        // Split the node
        new_node = (struct hp_code_node *)((uint8_t *)current + HP_CODE_NODE_SIZE + size);
        new_node->size = current->size - (HP_CODE_NODE_SIZE + size);
        new_node->next = current->next;

        // Update the current node (allocated block)
        current->size = size;
        current->next = NULL; // Allocated blocks should not link to free nodes

        // Update the free list
        if (previous == NULL) {
            hp_code_free_list = new_node;
        } else {
            previous->next = new_node;
        }
    } else {
        // Use the entire block without splitting
        if (previous == NULL) {
            hp_code_free_list = current->next;
        } else {
            previous->next = current->next;
        }
        current->next = NULL; // Allocated blocks should not link to free nodes
    }
    return (void *)((uint8_t *)current + HP_CODE_NODE_SIZE);
}

__ramfunc
void hp_code_free(void *ptr) {
    struct hp_code_node *current, *previous, *node_to_free;

    if (ptr == NULL) {
        return; // invalid memory pointer
    }

    node_to_free = (struct hp_code_node *)((uint8_t *)ptr - HP_CODE_NODE_SIZE);
    memset(ptr, 0, node_to_free->size);

    current = hp_code_free_list;
    previous = NULL;

    // Insert the freed node into the free list in address order
    while (current != NULL && current < node_to_free) {
        previous = current;
        current = current->next;
    }

    node_to_free->next = current;

    if (previous == NULL) {
        hp_code_free_list = node_to_free;
    } else {
        previous->next = node_to_free;
    }

    // Coalesce with next block if adjacent
    if (node_to_free->next != NULL && 
        (uint8_t *)node_to_free + HP_CODE_NODE_SIZE + node_to_free->size == (uint8_t *)node_to_free->next) {
        node_to_free->size += HP_CODE_NODE_SIZE + node_to_free->next->size;
        node_to_free->next = node_to_free->next->next;
    }

    // Coalesce with previous block if adjacent
    if (previous != NULL && 
        (uint8_t *)previous + HP_CODE_NODE_SIZE + previous->size == (uint8_t *)node_to_free) {
        previous->size += HP_CODE_NODE_SIZE + node_to_free->size;
        previous->next = node_to_free->next;
    }
}
