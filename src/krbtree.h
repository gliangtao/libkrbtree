/**
The MIT License (MIT)

Copyright (c) 2015 Liangtao Gao (gliangtao@gmail.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
/**
 * Keyed Red Black Tree
 *
 * Red Black tree implementation which uses "key" for identification
 * and comparation, and "data" for container of user defined data.
 * The reference materials include
 * http://mindlee.net/2011/08/21/red-black-tree/
 * and Julienne Walker's red-black tree tutorial at
 * http://eternallyconfuzzled.com/tuts/datastructures/jsw_tut_rbtree.aspx
 *
 * The original copyright information of
 * Julienne Walker's red-black tree tutorial is:
 *
  Red Black balanced tree library

    > Created (Julienne Walker): August 23, 2003
    > Modified (Julienne Walker): March 14, 2008

  This code is in the public domain. Anyone may
  use it or change it in any way that they see
  fit. The author assumes no responsibility for
  damages incurred through use of the original
  code or any variations thereof.

  It is requested, but not required, that due
  credit is given to the original author and
  anyone who has modified the code through
  a header comment, such as this one.
 *
 *
 * This implementation differs from the original tutorial in the following ways:
 * 1. Separate "key" from "data" for identification and comparation
 * 2. Embed the color of nodes into the node pointers to save RAM for a node
 * 3. Other logical adjustments
 */

#ifndef _KRBTREE_H_
#define _KRBTREE_H_

#include <stdint.h>

__BEGIN_DECLS

/**
 * Red Black tree functions
 */
/**
 * Create a keyed red-black tree.
 * If one parameter is NULL, the default parameter is used:
 * Default key_compare: returns "(int)((uintptr_t)key1 - (uintptr_t)key2)"
 * Default data_update: returns "(void*)rarNewData"
 * Default node_clean: does nothing
 * Default mem_alloc: returns "malloc(size)"
 * Default mem_free: returns "free(ptr)"
 *
 * @param key_compare Key comparer, returns -1 for "<", 0 for "==", 1 for ">"
 * @param data_update The data processor to handle the raw data
 * @param node_clean The cleaner for the key and the data
 * @param mem_alloc The memory allocator for a keyed red-black tree node
 * @param mem_free The memory deallocator for a keyed red-black tree node
 * @return The new keyed red-black tree on success, or NULL on error
 */
void* krbCreateTree(int   (*key_compare)(const void* key1, const void* key2),
                    void* (*data_update)(const void* key, void* oldData,
                                         const void* rawNewData),
                    void  (*node_clean)(void* key, void* data),
                    void* (*mem_alloc)(size_t size),
                    void  (*mem_free)(void *ptr));

/**
 * Destroy a keyed red-black tree, which is created via krbCreateTree()
 *
 * @param tree The keyed red-black tree to destroy
 */
void krbDestroyTree(void* tree);

/**
 * Dump a keyed red-black tree
 *
 * @param tree The keyed red-black tree created by krbCreateTree()
 * @return 0 if "tree" is invalid; positive black height if "tree" is valid
 */
unsigned int krbDumpTree(void* tree);

/**
 * Search for the data associated with a key in the keyed red-black tree
 *
 * @param tree The keyed red-black tree created by krbCreateTree()
 * @param key The key for search
 * @param data The data pointer when found
 * @param check_found Callback to check the found node
 * @return 1 if found, 0 if not found
 */
int krbSearch(const void* tree, const void* key, void** data,
              void (*check_found)(const void* key, void* data, void* params));

size_t krbSelectKeys(const void* tree, void** key_array, size_t key_array_size,
                     int (*select_key)(const void* key, void* data));
/**
 * Load or reload the the keyed red-black tree with the key and the raw data
 *
 * @param tree The keyed red-black tree created by krbCreateTree()
 * @param key The key for search
 * @param data The pointer to the new raw data to be processed
 * @return 1 on success, 0 on error
 */
int krbLoad(void* tree, const void* key, void* data);

/**
 * Unload the the keyed red-black tree with the key
 *
 * @param tree The keyed red-black tree created by krbCreateTree()
 * @param key The key for search
 * @return 1 if found and unloaded successfully, 0 otherwise
 */
int krbUnload(void* tree, const void* key);

/**
 * Get the number of nodes available in the tree
 *
 * @param tree The tree created by krbCreateTree()
 * @return The number of nodes available in the tree, or 0 if tree is NULL
 */
size_t krbSize(const void* tree);

__END_DECLS

#endif //_KRBTREE_H_
