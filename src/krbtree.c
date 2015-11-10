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
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "krbtree.h"

/**
 * NOTE: to enable unit test, "KRB_TREE_UNIT_TEST" needs to be defined
 * #define KRB_TREE_UNIT_TEST
 */

#define KRB_LOG(str...)             printf(str)
#define KRB_ABORT()                 abort()
#ifndef NDEBUG
#define KRB_DBG(str...)             KRB_LOG(str)
#else
#define KRB_DBG(str...)
#endif
#define ASSERT_TREE(tree)           assert(krbDumpTree(tree))

#ifndef WIN32
#define REQUEST_ALIGNMENT(align)    __attribute__((aligned(sizeof(uintptr_t))))
#else
#define REQUEST_ALIGNMENT(align)
#endif
#define RAND_R(seedp)               rand()

typedef int         (*key_compare_f)(const void* key1, const void* key2);
typedef void*       (*data_update_f)(const void* key, void* oldData,
                                     const void* rawNewData);
typedef void        (*node_clean_f)(void* key, void* data);
typedef void*       (*mem_alloc_f)(size_t size);
typedef void        (*mem_free_f)(void *ptr);

struct krbnode {
    /* Node key & color */
    void*           key;
    /* Node data */
    void*           data;
    /* Left (0) and right (1) link_colors */
    uintptr_t       link_color[2];
} REQUEST_ALIGNMENT(sizeof(uintptr_t));
typedef struct krbnode krbnode_t;

typedef struct krbtree {
    /* Tree root; always black */
    krbnode_t*      root;
    /* Number of items */
    size_t          count;
    /* Compare two keys */
    key_compare_f   key_compare;
    /* Process raw new data, return the processed new data */
    data_update_f   data_update;
    /* Finalize and deallocate a node */
    node_clean_f    node_clean;
    /* User specified memory allocation */
    mem_alloc_f     mem_alloc;
    /* User specified memory free, in pair with mem_alloc */
    mem_free_f      mem_free;
} krbtree_t;

/**
 * Conversions for tree/node/color
 */
#define TREE_ROOT(tree)             (((krbtree_t*)(tree))->root)
#define NOT_OF(value)               (~((uintptr_t)(value)))
#define COLOR_BIT                   1
#define REMOVE_COLOR(node_color)    ((uintptr_t)(node_color) & \
                                     NOT_OF(COLOR_BIT))
#define NODE(node_color)            ((krbnode_t*)REMOVE_COLOR(node_color))
/**
 * NOTE: the following node/color conversions presumes:
 * BLACK_COLOR is 0, RED_COLOR is COLOR_BIT
 */
#define PTR_TO_BLACK(node)          ((uintptr_t)(node))
#define PTR_TO_RED(node)            ((uintptr_t)(node) | COLOR_BIT)
#define IS_RED(node_color)          (0 != ((node_color) & COLOR_BIT))
#define IS_BLACK(node_color)        (0 == ((node_color) & COLOR_BIT))
#define SET_BLACK(node_color)       ((node_color) &= NOT_OF(COLOR_BIT))
#define SET_RED(node_color)         ((node_color) |= COLOR_BIT)
#define BLACK_NODE(node_color)      (NODE(node_color))

/**
 * Performs a single red-black rotation in the specified direction.
 * The black height is not changed
 *
 * @param root The existing root to rotate around
 * @param node_dir The direction to rotate (0 = anti-clockwise, 1 = clockwise)
 * @return The new root after rotation
 */
static inline uintptr_t singleRotateColor(uintptr_t root, int node_dir)
{
    /** Get the old root node pointer */
    krbnode_t* old_root = NODE(root);
    /** The new root is the child of the old root in direction "!node_dir" */
    krbnode_t* new_root = NODE(old_root->link_color[!node_dir]);
    /**
     * The new root's child in direction "node_dir"
     * becomes the child of the old root in direction "!node_dir"
     */
    old_root->link_color[!node_dir] = new_root->link_color[node_dir];
    /**
     * Mark the previous root as RED,
     * and let it be the child of the new root in node_dir "node_dir"
     */
    new_root->link_color[node_dir] = PTR_TO_RED(old_root);
    /**
     * We should return BLACK(save),
     * but note that "save == BLACK(save)" is always true
     */
    return ((uintptr_t)new_root);
}

/**
 * Performs a double red-black rotation in the specified direction.
 * The black height is not changed
 *
 * @param root The existing root to rotate around
 * @param node_dir The direction to rotate (0 = anti-clockwise, 1 = clockwise)
 * @return The new root after rotation
 */
static inline uintptr_t doubleRotateColor(uintptr_t root, int node_dir)
{
    /** Get the old root node pointer */
    krbnode_t* old_root = NODE(root);
    /**
     * Promote the subtree in direction "!node_dir"
     *
     * Firstly, rotate the subtree in direction "!node_dir"
     */
    old_root->link_color[!node_dir] =
            singleRotateColor(old_root->link_color[!node_dir], !node_dir);
    /** Rotate the tree in node_dir "node_dir" */
    return singleRotateColor(root, node_dir);
}

/**
 * Performs a single red-black rotation in the specified direction,
 * but keeps the nodes' color. The black height is not changed
 *
 * @param root The existing root to rotate around
 * @param node_dir The direction to rotate (0 = anti-clockwise, 1 = clockwise)
 * @return The new root and color after rotation
 */
static inline uintptr_t singleRotateNoColor(uintptr_t root, int node_dir)
{
    /** Get the old root node pointer */
    krbnode_t* old_root = NODE(root);
    uintptr_t new_root_color = old_root->link_color[!node_dir];
    /** The new root is the child of the old root in direction "!node_dir" */
    krbnode_t* new_root = NODE(new_root_color);
    /**
     * The new root's child in direction "node_dir"
     * becomes the child of the old root in direction "!node_dir"
     */
    old_root->link_color[!node_dir] = new_root->link_color[node_dir];
    /**
     * The previous root becomes the child of the new root
     * in direction "node_dir"
     */
    new_root->link_color[node_dir] = root;
    return new_root_color;
}

/**
 * Performs a double red-black rotation in the specified direction,
 * but keeps the nodes' color. The black height is not changed
 *
 * @param root The existing root to rotate around
 * @param node_dir The direction to rotate (0 = anti-clockwise, 1 = clockwise)
 * @return The new root and color after rotation
 */
static inline uintptr_t doubleRotateNoColor(uintptr_t root, int node_dir)
{
    /** Get the old root node pointer */
    krbnode_t* old_root = NODE(root);
    /**
     * Promote the subtree in node_dir "!node_dir"
     *
     * Firstly, rotate the subtree in node_dir "!node_dir"
     */
    old_root->link_color[!node_dir] =
            singleRotateNoColor(old_root->link_color[!node_dir], !node_dir);
    /** Rotate the tree in node_dir "node_dir" */
    return singleRotateNoColor(root, node_dir);
}

/**
 * Allocate a plain/raw node
 *
 * @param key The key for the new node
 * @param tp The keyed red-black tree
 * @return The new plain node (in BLACK color) on success, or NULL on error
 */
static krbnode_t* allocPlainNode(const void* key, krbtree_t* tp)
{
    krbnode_t* np = NULL;
    if (tp != NULL) {
        assert(tp->mem_alloc != NULL);
        np = (krbnode_t*)(tp->mem_alloc(sizeof(krbnode_t)));
    } else {
        np = (krbnode_t*)(malloc(sizeof(krbnode_t)));
    }
    if (np != NULL) {
        np->link_color[0] = 0;
        np->link_color[1] = 0;
        np->key = (void*)key;
        np->data = NULL;
    }
    return np;
}

/**
 * Free the memory occupied by a plain/raw node
 *
 * @param node The node whose memory needs to be freed
 * @param tp The keyed red-black tree
 */
static void freePlainNode(krbnode_t* node, krbtree_t* tp)
{
    KRB_DBG("Deleted node %p: key %p, 0x%lx, 0x%lx\n",
            node, node->key, node->link_color[0], node->link_color[1]);
    if (tp != NULL) {
        assert(tp->mem_free != NULL);
        tp->mem_free(node);
    } else {
        free(node);
    }
}

static int default_key_compare(const void* key1, const void* key2)
{
    return (int)((uintptr_t)key1 - (uintptr_t)key2);
}

static void* default_data_update(const void* key, void* oldData,
                                 const void* rarNewData)
{
    (void)(key);
    (void)(oldData);
    return (void*)rarNewData;
}

static void default_node_clean(void* key, void* data)
{
    (void)(key);
    (void)(data);
}

#define default_mem_alloc   malloc
#define default_mem_free    free

/**
 * Red Black tree functions
 */
/**
 * Create a keyed red-black tree
 *
 * @param key_compare Key comparer, returns -1 for "<", 0 for "==", 1 for ">"
 * @param data_update The data processor to handle the raw data
 * @param node_clean The cleaner for the key and the data
 * @return The new keyed red-black tree on success, or NULL on error
 */
void* krbCreateTree(key_compare_f key_compare,
                    data_update_f data_update,
                    node_clean_f node_clean,
                    mem_alloc_f mem_alloc,
                    mem_free_f mem_free)
{
    krbtree_t* tp = (krbtree_t*)malloc(sizeof(krbtree_t));
    if (tp != NULL) {
        tp->root        =   NULL;
        tp->count       =   0;
        tp->key_compare =   key_compare ? key_compare   : default_key_compare;
        tp->data_update =   data_update ? data_update   : default_data_update;
        tp->node_clean  =   node_clean  ? node_clean    : default_node_clean;
        tp->mem_alloc   =   mem_alloc   ? mem_alloc     : default_mem_alloc;
        tp->mem_free    =   mem_free    ? mem_free      : default_mem_free;
    }
    return tp;
}

/**
 * Destroy a keyed red-black tree, which is created via krbCreateTree()
 *
 * @param tree The keyed red-black tree to destroy
 */
void krbDestroyTree(void* tree)
{
    if (tree != NULL) {
        krbtree_t* tp = (krbtree_t*)tree;
        node_clean_f node_clean = tp->node_clean;
        krbnode_t* saved;
        krbnode_t* np = tp->root;
        /**
         * Rotate away the left child node so that we can treat this
         * like the destruction of a node list
         */
        while (np != NULL) {
            if ((saved = NODE(np->link_color[0])) == NULL) {
                /**
                 * No left link_colors, just kill the node and move on
                 */
                saved = NODE(np->link_color[1]);
                node_clean(np->key, np->data);
                freePlainNode(np, tp);
            } else {
                /**
                 * Rotate clockwise to lift the left child node and check again
                 */
                np->link_color[0] = saved->link_color[1];
                saved->link_color[1] = PTR_TO_BLACK(np);
            }
            np = saved;
        }
        free(tp);
    }
}

static inline int COLOR_CH(uintptr_t node_color)
{
    return (IS_RED(node_color)) ? 'R' : 'B';
}

static void dumpOneNodeColor(uintptr_t node_color, int active_level)
{
    int i;
    krbnode_t* node = NODE(node_color);
    krbnode_t* left = NODE(node->link_color[0]);
    krbnode_t* right = NODE(node->link_color[1]);
    for(i = active_level; i > 0; i--) {
        KRB_LOG("    ");
    }
    KRB_LOG("%p(%p,%c): ", node, node->key, COLOR_CH(node_color));
    if (left) {
        KRB_LOG("%p(%p,%c), ",
                left, left->key, COLOR_CH(node->link_color[0]));
    } else {
        KRB_LOG("null, ");
    }
    if (right) {
        KRB_LOG("%p(%p,%c)\n",
                right, right->key, COLOR_CH(node->link_color[1]));
    } else {
        KRB_LOG("null\n");
    }
}

static unsigned int dumpSubTree(uintptr_t node_color, int active_level)
{
    unsigned long left_height;
    unsigned long right_height;
    krbnode_t* node = NODE(node_color);
    uintptr_t left_color;
    uintptr_t right_color;
    if (!node) {
        /**
         * NULL node has 1 black height
         */
        return 1;
    }

    dumpOneNodeColor(node_color, active_level);

    left_color = node->link_color[0];
    right_color = node->link_color[1];
    if (IS_RED(node_color) && (IS_RED(left_color) || IS_RED(right_color))) {
        /**
         * Red violation
         */
        KRB_DBG("Red violation\n");
        KRB_ABORT();
        return 0;
    }
    left_height = dumpSubTree(left_color, 1 + active_level);
    if (!left_height) {
        KRB_ABORT();
        return 0;
    }
    right_height = dumpSubTree(right_color, 1 + active_level);
    if ((!right_height) || (left_height != right_height)) {
        KRB_ABORT();
        return 0;
    }
    return left_height + IS_BLACK(node_color);
}

/**
 * Dump a keyed red-black tree
 *
 * @param tree The keyed red-black tree created by krbCreateTree()
 * @return 0 if "tree" is invalid; positive black height if "tree" is valid
 */
unsigned int krbDumpTree(void* tree)
{
    unsigned int blackHeight = 0;
    krbnode_t* root = NULL;
    size_t count = 0;
    KRB_LOG("%s(%p) ...\n", __FUNCTION__, tree);
    if (tree != NULL) {
        uintptr_t root_color = (uintptr_t)(((krbtree_t*)tree)->root);
        if (IS_BLACK(root_color)) {
            blackHeight = dumpSubTree(root_color, 0);
        }
        root = NODE(root_color);
        count = ((krbtree_t*)tree)->count;
        if (blackHeight > 0) {
            size_t expected_max_nodes = (size_t)1 << ((blackHeight - 1) << 1);
            if (expected_max_nodes < count) {
                KRB_LOG("Red/black violations? Black height %d, count %lu > expected %lu\n",
                        blackHeight, count, expected_max_nodes);
                blackHeight = 0;
            }
        }
    }
    KRB_LOG("%s(%p): root %p, %lu nodes\n", __FUNCTION__, tree, root, count);
    return blackHeight;
}

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
              void (*check_found)(const void* key, void* data, void* params))
{
    krbtree_t* tp = (krbtree_t*)tree;
    if ((tp != NULL) && (tp->root != NULL)) {
        key_compare_f key_compare = tp->key_compare;
        krbnode_t* np = tp->root;
        while (np != NULL) {
            int cmp_ret = key_compare(np->key, key);
            if (cmp_ret != 0) {
                /**
                 * If the tree supports duplicates, they should be
                 * chained to the right subtree for this to work
                 */
                np = NODE(np->link_color[cmp_ret < 0]);
            } else {
                break;
            }
        }
        if (np != NULL) {
            void* params;
            if (data) {
                params = *data;
                *data = np->data;
            } else {
                params = NULL;
            }
            if (check_found != NULL) {
                check_found(np->key, np->data, params);
            }
            return 1;
        }
    }
    return 0;
}

static int default_select_key(const void* key, void* data)
{
    (void)(key);
    (void)(data);
    return 1;
}

size_t krbSelectKeys(const void* tree, void** key_array, size_t key_array_size,
                     int (*select_key)(const void* key, void* data))
{
    void** key_ptr = key_array;
    void** key_ptr_end = key_array + key_array_size;
    krbtree_t* tp = (krbtree_t*)tree;
    if ((tp != NULL) && (tp->root != NULL)) {
        krbnode_t* path[sizeof(void*) * 8 * 2];
        krbnode_t** pptr = path;
        if (NULL == select_key) {
            select_key = default_select_key;
        }
        for (*(pptr++) = tp->root; pptr != path; ) {
            krbnode_t* child;
            krbnode_t* np = *(--pptr);
            if ((select_key(np->key, np->data) != 0) && (key_array != NULL)) {
                *(key_ptr++) = np->key;
                if (key_ptr >= key_ptr_end) {
                    break;
                }
            }
            if ((child = NODE(np->link_color[1])) != NULL) {
                *(pptr++) = child;
            }
            if ((child = NODE(np->link_color[0])) != NULL) {
                *(pptr++) = child;
            }
        }
    }
    return (key_ptr - key_array);
}

/**
 * Load or reload the the keyed red-black tree with the key and the raw data
 *
 * @param tree The keyed red-black tree created by krbCreateTree()
 * @param key The key for search
 * @param data The pointer to the new raw data to be processed
 * @return 1 on success, 0 on error
 */
int krbLoad(void* tree, const void* key, void* rawData)
{
    krbtree_t* tp;
    krbnode_t* node;
    if (!tree) {
        return 0;
    }

    tp = (krbtree_t*)tree;
    if (NULL == tp->root) {
        if (NULL == (node = allocPlainNode(key, tp))) {
            return 0;
        }
        /**
         * Note: node is BLACK
         */
        tp->root = node;
        tp->count++;
    } else {
        /** Fake tree root used in the track */
        krbnode_t head;
        krbnode_t* great_grand_parent;
        krbnode_t* grand_parent;
        krbnode_t* parent;
        uintptr_t node_color;
        uintptr_t parent_color;
        int node_dir = 0;
        int cmp_ret;
        key_compare_f key_compare = tp->key_compare;

        /**
         * Prepare for the first node in the track
         */
        node = tp->root;
        node_color = PTR_TO_BLACK(node);
        head.key = NULL;
        head.data = NULL;
        head.link_color[0] = PTR_TO_BLACK(NULL);
        head.link_color[1] = node_color;
        /**
         * In fact, we ensures "great_grand_parent != NULL",
         * and "IS_BLACK(head.link_color[1])"
         */
        great_grand_parent = &head;
        grand_parent = NULL;
        parent_color = PTR_TO_BLACK(parent = NULL);

        /**
         * Track down the tree and make sure:
         * 1. There are no consecutive RED nodes in the track
         * 2. "head.link_color[1]" is always BLACK
         *
         * Push BLACK nodes down along the track with rotations and color flips
         */
        for (;;) {
            do {
                if (NULL == node) {
                    /**
                     * Good place for the new node. Insert the new node here
                     */
                    if (NULL == (node = allocPlainNode(key, tp))) {
                        /**
                         * Update the root (it may be different
                         * from the old root), and mark it black
                         */
                        tp->root = BLACK_NODE(head.link_color[1]);
                        /**
                         * Fail to create the new node.
                         * Return to report the error
                         */
                        return 0;
                    }
                    tp->count++;
                } else if (IS_RED(node->link_color[0]) &&
                           IS_RED(node->link_color[1])) {
                    /**
                     * Good time to mark the children BLACK
                     */
                    SET_BLACK(node->link_color[0]);
                    SET_BLACK(node->link_color[1]);
                } else {
                    /**
                     * Break out as color flip is not applicable here
                     */
                    break;
                }
                assert((NULL != NODE(head.link_color[1])) &&
                       IS_BLACK(head.link_color[1]));
                /**
                 * Usually if "node" is not at root, mark it RED;
                 * BUT if "node" is really at root,
                 * keep it BLACK - a good time to increase the black height!
                 */
                if ((krbnode_t*)(head.link_color[1]) != node) {
                    node_color = PTR_TO_RED(node);
                } else {
                    node_color = PTR_TO_BLACK(node);
                }
                if (parent != NULL) {
                    parent->link_color[node_dir] = node_color;
                }
            } while (0);

            if (IS_RED(parent_color) && IS_RED(node_color)) {
                /**
                 * As we track down the tree, we can prove
                 * "grand_parent" and "parent" must not be both RED.
                 * But if "parent" is RED, and we recently changed "node"
                 * to RED, there will be RED violation.
                 * Let's fix this kind of RED violation
                 */
                uintptr_t new_subroot_color;
                int grand_parent_dir;
                int parent_dir;
                /**
                 * A NULL code is BLACK. Since parent_color is RED,
                 * "parent" must non-NULL; and "parent" must be a child node
                 * of another node - the "grand_parent".
                 * So "grand_parent" must also be non-NULL and BLACK
                 */
                assert((parent != NULL) && (grand_parent != NULL));
                grand_parent_dir = (NODE(great_grand_parent->link_color[0]) !=
                                    grand_parent);
                parent_dir = (NODE(grand_parent->link_color[0]) != parent);
                /**
                 * Before rotation, "grand_parent" was the root of
                 * the old subtree.
                 * After rotation, either "node" or "parent" becomes
                 * the root of the new subtree
                 *
                 * Check if "node" and "parent" are in same direction
                 * "(node_dir == parent_dir)"
                 */
                if (node_dir != parent_dir) {
                    /**
                     * Double rotate. "node" will become the root of
                     * the subtree after rotation
                     *
                     * "node" will turn BLACK
                     *
                     * Set "parent" and "grand_parent" to NULL
                     */
                    parent = NULL;
                    SET_BLACK(node_color);
                    new_subroot_color =
                            doubleRotateColor(PTR_TO_BLACK(grand_parent),
                                              !parent_dir);
                } else {
                    /**
                     * Single rotate. "parent" will become the root of
                     * the subtree after rotation
                     *
                     * "node" will still be a RED child of "parent"
                     *
                     * "parent" will turn BLACK
                     *
                     * Set "grand_parent" to NULL
                     */
                    new_subroot_color =
                            singleRotateColor(PTR_TO_BLACK(grand_parent),
                                              !parent_dir);
                }
                assert(IS_BLACK(new_subroot_color));
                great_grand_parent->link_color[grand_parent_dir] =
                        new_subroot_color;
                grand_parent = NULL;
            }

            /**
             * For a keyed red-black tree, every node must have a unique key
             * Stop working if we found a matching node
             */
            if (0 == (cmp_ret = key_compare(node->key, key))) {
                break;
            }

            /**
             * Prepare for the next node in the track
             */

            /**
             * Make sure "great_grand_parent" is always non-NULL
             */
            if (grand_parent != NULL) {
                great_grand_parent = grand_parent;
            }
            grand_parent = parent;
            parent_color = node_color;
            parent = node;

            node_dir = (cmp_ret < 0);
            node_color = parent->link_color[node_dir];
            node = NODE(node_color);
        }

        /**
         * Update the root (it may be different from the old root),
         * and mark it black
         */
        tp->root = BLACK_NODE(head.link_color[1]);
    }

    node->data = tp->data_update(node->key, node->data, rawData);
    return 1;
}

/**
 * Unload the the keyed red-black tree with the key
 *
 * @param tree The keyed red-black tree created by krbCreateTree()
 * @param key The key for search
 * @param params Optional parameters
 * @return 1 if found and unloaded successfully, 0 otherwise
 */
int krbUnload(void* tree, const void* key)
{
    krbnode_t* node;
    krbtree_t* tp = (krbtree_t*)tree;
    krbnode_t* match = NULL;
    if ((NULL != tp) && (NULL != tp->root)) {
        /** Fake tree root used in the track */
        krbnode_t head;
        krbnode_t* grand_parent;
        krbnode_t* parent;
        krbnode_t* child;
        int child_dir;
        int node_dir;
        uintptr_t node_color;
        uintptr_t child_color;
        int cmp_ret;
        key_compare_f key_compare = tp->key_compare;

        /**
         * Prepare for the first node in the track
         */
        head.link_color[0] = PTR_TO_BLACK(NULL);
        head.link_color[1] = PTR_TO_BLACK(tp->root);
        node = &head;
        parent = NULL;
        grand_parent = NULL;
        child_dir = 1;
        child_color = node->link_color[child_dir];
        child = NODE(child_color);
        /**
         * Track down the tree and make sure there are
         * no consecutive BLACK nodes in the track
         *
         * Push RED nodes down along the track with rotations and color flips
         */
        while (child != NULL) {
            assert(node != NULL);
            /**
             * Prepare for the next node in the track
             */
            grand_parent = parent;
            parent = node;

            node_dir = child_dir;
            node_color = child_color;
            node = child;

            cmp_ret = key_compare(node->key, key);
            child_dir = (cmp_ret < 0);
            child_color = node->link_color[child_dir];
            child = NODE(child_color);
            /**
             * If the node with matching key is found, record it
             * and keep tracking down the tree.
             * we will find the node with adjacent key in the direction
             */
            if (!cmp_ret) {
                match = NODE(node);
            }
            /**
             * Note: "child" can be NULL, and a NULL node has BLACK_COLOR
             */
            if (IS_BLACK(node_color) && IS_BLACK(child_color)) {
                /**
                 *    1B
                 *   /  \
                 *  0?  2B
                 *
                 * -- OR --
                 *
                 *    1B
                 *   /  \
                 *  0B   2?
                 */
                if (IS_RED(node->link_color[!child_dir])) {
                    uintptr_t new_parent_color;
                    /**
                     * "node" becomes RED; "child" keeps unchanged;
                     * the new subtree root, which was previously the other
                     * child of "node", becomes the new "parent"
                     *      3B(n)       1B
                     *     /  \   -->  /  \
                     *   1R    4B(c)  0B   3R(n)
                     *  /  \              /  \
                     * 0B  2B            2B  4B(c)
                     *
                     *      -- OR --
                     *
                     *      1B(n)            3B
                     *     /  \   -->      /    \
                     *   0B(c) 3R        1R(n)  4B
                     *        /  \      /   \
                     *       2B  4B    0B(c) 2B
                     */
                    new_parent_color =
                            singleRotateColor(PTR_TO_BLACK(node),
                                              child_dir);
                    parent->link_color[node_dir] = new_parent_color;
                    parent = (krbnode_t*)(new_parent_color);
                } else if (NODE(parent->link_color[!node_dir]) == NULL) {
                    SET_RED(node_color);
                    parent->link_color[node_dir] = node_color;
                } else {
                    /**
                     * "node" is BLACK, and its children are both BLACK
                     *
                     *    1B   (NOTE: can be either root or non-root node)
                     *   /  \
                     * 0B    2B
                     */
                    if (grand_parent != NULL) {
                        /**
                         * In this case, "parent" must be RED, since we can
                         * prove (or conclude) there are no consecutive
                         * BLACK nodes in the track
                         *
                         *        3R(p)
                         *      /    \
                         *    1B(n)  4B(s)
                         *   /  \
                         * 0B    2B
                         */
                        /**
                         * Both children are BLACK, and "node" is not at root
                         */
                        krbnode_t* sibling;
                        uintptr_t sibling_child_color1;
                        uintptr_t sibling_child_color2;
                        sibling = NODE(parent->link_color[!node_dir]);
                        assert(sibling != NULL);
                        sibling_child_color1 = sibling->link_color[node_dir];
                        sibling_child_color2 = sibling->link_color[!node_dir];
                        int parent_dir =
                                (NODE(grand_parent->link_color[0]) != parent);
                        if (IS_BLACK(sibling_child_color1) &&
                            IS_BLACK(sibling_child_color2)) {
                            /**
                             *        3R                   3B
                             *      /    \               /    \
                             *    1B(n)   5B(s)  -->  1R(n)   5R(s)
                             *   /  \    /  \        /  \    /  \
                             * 0B    2B 4B   6B     0B   2B 4B   6B
                             */
                            /**
                             * The reverse color flip case
                             *
                             * We SHOULD not do the reverse color flip if
                             * "parent" is BLACK. However, "parent" is already
                             * proved to be RED, so it's valid to skip the check
                             * "(IS_RED(grand_parent->link_color[parent_dir]))"
                             * before changing the color
                             */
                            SET_BLACK(grand_parent->link_color[parent_dir]);
                            SET_RED(parent->link_color[!node_dir]);
                        } else {
                            krbnode_t* new_grand_parent;
                            if (IS_RED(sibling_child_color1)) {
                                /**
                                 *        3R                 3R
                                 *      /    \             /    \
                                 *    1B(n)   7B(s) -->  1B(n)  5R
                                 *   /  \    /  \       /  \    / \
                                 * 0B    2B 5R   8B   0B    2B 4B  7B
                                 *         /  \                   /  \
                                 *        4B   6B                6B   8B
                                 *
                                 *                              5R
                                 *                            /    \
                                 *          3R              3B      7B
                                 *        /    \           /  \    /  \
                                 *      1B(n)  5R   -->  1R(n) 4B 6B   8B
                                 *     /  \    / \      /  \
                                 *   0B    2B 4B  7B  0B    2B
                                 *               /  \
                                 *              6B   8B
                                 */
                                new_grand_parent = NODE(doubleRotateNoColor(
                                        PTR_TO_RED(parent), node_dir));
                            } else {
                                /** (IS_RED(sibling_child_color2)) */
                                /**
                                 *                               5R
                                 *                             /    \
                                 *        3R                 3B      7B
                                 *      /    \              /  \    /  \
                                 *    1B(n)   5B(s)  -->  1R(n) 4B 6B  8B
                                 *   /  \    /  \        /  \
                                 *  0B  2B  4B   7R     0B  2B
                                 *              /  \
                                 *             6B  8B
                                 */
                                new_grand_parent = NODE(singleRotateNoColor(
                                        PTR_TO_RED(parent), node_dir));
                            }
                            /**
                             * After rotation, "parent" is still the parent of
                             * "node", so we don't need to recalculate "parent";
                             * "grand_parent" becomes the new
                             * "great_grand_parent"
                             *
                             * singleRotateRedRoot() has set
                             * new_parent->link_color[parent_dir] to BLACK
                             */
                            SET_BLACK(new_grand_parent->link_color[0]);
                            SET_BLACK(new_grand_parent->link_color[1]);
                            grand_parent->link_color[parent_dir] =
                                    PTR_TO_RED(new_grand_parent);
                        }
                        /**
                         * Don't forget to mark "node" RED
                         * to keep red-black balance
                         */
                        SET_RED(parent->link_color[node_dir]);
                    } else {
                        /**
                         * In this case, "node" must be root,
                         * and both its children must be BLACK,
                         * a good time to decrease the black height!
                         * Let's mark the tree root RED
                         *
                         *    1B(n)        1R(n)
                         *   /  \    -->  /  \
                         *  0B  2B       0B  2B
                         */
                        assert(node == NODE(head.link_color[1]));
                        SET_RED(node_color);
                        parent->link_color[node_dir] = node_color;
                    }
                }
            }
        }

        /**
         * What is interesting here:
         * Instead of replacing and remove the match node,
         * we remove "node" which has 0 or 1 child
         */
        if (match != NULL) {
            tp->node_clean(match->key, match->data);
            /**
             * The above "while()" loop ensures
             * "NODE(node->link_color[child_dir]) == NULL",
             * so we promote the child "node->link_color[!child_dir]"
             */
            child_color = node->link_color[!child_dir];
            assert(!child_color || IS_RED(child_color));
            child = NODE(child_color);
            if (match != node) {
                match->key = node->key;
                match->data = node->data;
            }
            /**
             * Q: Why we need recalculate "node_dir"?
             * A: Because it might get obsoleted by the last possible rotation
             */
            node_dir = (NODE(parent->link_color[0]) != node);
            parent->link_color[node_dir] = PTR_TO_BLACK(child);
            KRB_DBG("key %p, match %p, old_root %p, new_root %p," \
                    " grand_parent %p, parent %p," \
                    " parent->link_color[node_dir] %p, node %p, child %p\n", \
                    key, match, tp->root, BLACK_NODE(head.link_color[1]), \
                    grand_parent, parent, \
                    (void*)(parent->link_color[node_dir]), node, child);
            freePlainNode(node, tp);
            /**
             * Update the count of nodes, as a node has perished
             */
            tp->count--;
        } else {
            KRB_DBG("NO matching node for key %p\n", key);
        }

        /**
         * Update the root (it may be different from the old root)
         * Mark the new root black
         */
        tp->root = BLACK_NODE(head.link_color[1]);
        ASSERT_TREE(tree);
        KRB_DBG("New root %p, new count %u\n",
                tp->root, (unsigned int)tp->count);
    }

    /**
     * Return 1 if a match node is found and deleted, 0 otherwise
     */
    return (NULL != match);
}

/**
 * Get the number of nodes available in the tree
 *
 * @param tree The tree created by krbCreateTree()
 * @return The number of nodes available in the tree, or 0 if tree is NULL
 */
size_t krbSize(const void* tree)
{
    krbtree_t* tp = (krbtree_t*)tree;
    return (tp != NULL) ? (tp->count) : 0;
}

#ifdef KRB_TREE_UNIT_TEST
#include <time.h>
static uintptr_t* restore_keys(unsigned int* pTotal)
{
    uintptr_t* keys = NULL;
    FILE* fp = fopen("keys.txt", "r");
    if (fp != NULL) {
        unsigned int total;
        char lineBuf[64];
        if (fgets(lineBuf, sizeof(lineBuf), fp)) {
            sscanf(lineBuf, "%x", &total);
            keys = (uintptr_t*)malloc(total * sizeof(uintptr_t));
            if (keys != NULL) {
                unsigned int i;
                unsigned long int value;
                for (i = 0; i < total; i++) {
                    if (!fgets(lineBuf, sizeof(lineBuf), fp)) {
                        total = i;
                        break;
                    }
                    sscanf(lineBuf, "%lx", &value);
                    keys[i] = (uintptr_t)value;
                }
                if (!total) {
                    free(keys);
                    keys = NULL;
                } else if (pTotal != NULL) {
                    *pTotal = total;
                }
            }
        }
        fclose(fp);
    }
    return keys;
}

static void save_keys(unsigned int total, uintptr_t* keys)
{
    FILE* fp = fopen("keys.txt", "w");
    if (fp != NULL) {
        unsigned int i;
        fprintf(fp, "%x", total);
        for (i = 0; i < total; i++) {
            fprintf(fp, "\n%lx", (unsigned long int)keys[i]);
        }
        fclose(fp);
    }
}

#define DEFAULT_MAX_NODES   30

static int test_case_0(unsigned int max_nodes)
{
    void* data = NULL;
    void* tree;
    tree = krbCreateTree(NULL, NULL, NULL, NULL, NULL);
    if (tree != NULL) {
        uintptr_t* keys = NULL;
        unsigned int count;
        struct timeval tvStart;
        struct timeval tvEnd;
        unsigned int usDiff;
        KRB_LOG("Verifying red-black tree with %u nodes in %s()\n",
                max_nodes, __FUNCTION__);
        if (!max_nodes) {
            keys = restore_keys(&max_nodes);
            if (!keys) {
                max_nodes = DEFAULT_MAX_NODES;
            }
        }
        if (!keys) {
            unsigned int seed = (unsigned int)time(0);
            keys = (uintptr_t*)malloc(max_nodes * sizeof(uintptr_t));
            srand(seed);
            for (count = 0; count < max_nodes; count++) {
                keys[count] = RAND_R(&seed);
            }
            save_keys(max_nodes, keys);
        }
        gettimeofday(&tvStart, NULL);
        for (count = 0; count < max_nodes; count++) {
            krbLoad(tree, (void*)(keys[count]), &data);
#ifndef NDEBUG
            if (!krbDumpTree(tree)) {
                KRB_DBG("Red-black tree invalid after inserting"
                        " %dth key 0x%lx\n", count, keys[count]);
                KRB_ABORT();
            }
#endif
        }
        gettimeofday(&tvEnd, NULL);
        usDiff = 1000 * 1000 * (tvEnd.tv_sec - tvStart.tv_sec);
        if (tvEnd.tv_usec < tvStart.tv_usec) {
            usDiff += ((1000 * 1000 + tvEnd.tv_usec) - tvStart.tv_usec);
            usDiff -= 1000 * 1000;
        } else {
            usDiff += (tvEnd.tv_usec - tvStart.tv_usec);
        }
        KRB_DBG("Created tree:\n");
        if (!krbDumpTree(tree)) {
            KRB_DBG("Red-black tree invalid after inserting %dth key 0x%lx\n",
                    count, keys[count]);
            KRB_ABORT();
        }
        KRB_DBG("END of created tree\n");
        KRB_LOG("%u nodes processed by %s() in %u us, %fn/s\n",
                max_nodes, "krbLoad",
                usDiff, ((1000000.0 * (double)max_nodes)/(double)usDiff));
#ifndef NDEBUG
        KRB_DBG("Saved keys = { ");
        for (count = 0; count < max_nodes - 1; count++) {
            KRB_DBG("0x%lx, ", (keys[count]));
        }
        KRB_DBG("0x%lx };\n", (keys[count]));

#endif
        gettimeofday(&tvStart, NULL);
        for (count = 0; count < max_nodes; count++) {
            if (!krbSearch(tree, (void*)(keys[count]), NULL, NULL)) {
                KRB_DBG("!!! Red-black tree missing %dth key 0x%lx\n",
                        count, keys[count]);
            }
        }
        gettimeofday(&tvEnd, NULL);
        usDiff = 1000 * 1000 * (tvEnd.tv_sec - tvStart.tv_sec);
        if (tvEnd.tv_usec < tvStart.tv_usec) {
            usDiff += ((1000 * 1000 + tvEnd.tv_usec) - tvStart.tv_usec);
            usDiff -= 1000 * 1000;
        } else {
            usDiff += (tvEnd.tv_usec - tvStart.tv_usec);
        }
        KRB_LOG("%u nodes processed by %s() in %u us, %fn/s\n",
                max_nodes, "krbSearch",
                usDiff, ((1000000.0 * (double)max_nodes)/(double)usDiff));

        gettimeofday(&tvStart, NULL);
        for (count = 0; count < max_nodes; count++) {
            if (!krbUnload(tree, (void*)(keys[count]))) {
                KRB_DBG("XXX Red-black tree missing %dth key 0x%lx\n",
                        count, keys[count]);
            } else {
                KRB_DBG("RRR Removed %dth key 0x%lx in Red-black tree\n",
                        count, keys[count]);
            }
        }
        gettimeofday(&tvEnd, NULL);
        usDiff = 1000 * 1000 * (tvEnd.tv_sec - tvStart.tv_sec);
        if (tvEnd.tv_usec < tvStart.tv_usec) {
            usDiff += ((1000 * 1000 + tvEnd.tv_usec) - tvStart.tv_usec);
            usDiff -= 1000 * 1000;
        } else {
            usDiff += (tvEnd.tv_usec - tvStart.tv_usec);
        }
        KRB_LOG("%u nodes processed by %s() in %u us, %fn/s\n",
                max_nodes, "krbUnload",
                usDiff, ((1000000.0 * (double)max_nodes)/(double)usDiff));
        free(keys);
        krbDestroyTree(tree);
    }
    return 0;
}

typedef int (*test_case_f)(unsigned int max_nodes);

int main(int argc, char** argv)
{
    unsigned int max_nodes;
    unsigned int i;
    test_case_f test_cases[] = {
        test_case_0,
        };
    if (argc > 1) {
        max_nodes = (unsigned int)(strtoul(argv[1], NULL, 10));
    } else {
        max_nodes = 0;
    }
    for (i = 0; i < sizeof(test_cases)/sizeof(test_cases[0]); i++) {
        KRB_LOG("Test case %d: %s\n",
                i, test_cases[i](max_nodes) ? "FAILED" : "SUCCESS");
    }
    return 0;
}
#endif
