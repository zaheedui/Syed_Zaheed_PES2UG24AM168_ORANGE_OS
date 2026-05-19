// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

// Forward declarations
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; // Malformed data

        // Parse mode into an isolated buffer
        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Helper for qsort to sort index entries by path
static int compare_index_entries_by_path(const void *a, const void *b) {
    return strcmp(((const IndexEntry *)a)->path, ((const IndexEntry *)b)->path);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    // Estimate max size: (6 bytes mode + 1 byte space + 256 bytes name + 1 byte null + 32 bytes hash) per entry
    size_t max_size = tree->count * 296; 
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    // Create a mutable copy to sort entries (Git requirement)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        // Write mode and name (%o writes octal correctly for Git standards)
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 to step over the null terminator written by sprintf
        
        // Write binary hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Helper function to build a tree from a subset of index entries at a given directory depth
// depth: 0 for root, 1 for subdirs, etc.
// prefix: current directory path prefix (empty for root)
// entries: sorted array of index entries
// count: number of entries in the array
// Returns ObjectID of the written tree on success, zeros on failure
static ObjectID write_tree_level(const IndexEntry *entries, int count, int depth, const char *prefix) {
    ObjectID result = {0};
    Tree tree = {0};
    
    // Group entries by their immediate subdirectory or file
    int i = 0;
    while (i < count && tree.count < MAX_TREE_ENTRIES) {
        const IndexEntry *entry = &entries[i];
        
        // Calculate the path relative to current depth
        const char *rel_path = entry->path;
        if (depth > 0 && prefix[0] != '\0') {
            size_t prefix_len = strlen(prefix);
            if (strncmp(rel_path, prefix, prefix_len) != 0 || rel_path[prefix_len] != '/') {
                i++;
                continue;
            }
            rel_path = entry->path + prefix_len + 1;
        }
        
        // Find the next path separator
        char *slash = strchr(rel_path, '/');
        
        TreeEntry *tree_entry = &tree.entries[tree.count];
        
        if (slash == NULL) {
            // This is a file, not a directory
            size_t rel_len = strlen(rel_path);
            size_t copy_len = rel_len < sizeof(tree_entry->name) - 1 ? rel_len : sizeof(tree_entry->name) - 1;
            memcpy(tree_entry->name, rel_path, copy_len);
            tree_entry->name[copy_len] = '\0';
            tree_entry->mode = entry->mode;
            tree_entry->hash = entry->hash;
            tree.count++;
            i++;
        } else {
            // This is a directory - collect all entries in it and create a subtree
            size_t dir_name_len = slash - rel_path;
            size_t copy_len = dir_name_len < sizeof(tree_entry->name) - 1 ? dir_name_len : sizeof(tree_entry->name) - 1;
            memcpy(tree_entry->name, rel_path, copy_len);
            tree_entry->name[copy_len] = '\0';
            tree_entry->name[dir_name_len] = '\0';
            
            // Find all entries that belong to this subdirectory
            char new_prefix[512];
            if (prefix[0] != '\0') {
                snprintf(new_prefix, sizeof(new_prefix), "%s/%s", prefix, tree_entry->name);
            } else {
                strncpy(new_prefix, tree_entry->name, sizeof(new_prefix) - 1);
            }
            
            int subdir_start = i;
            int subdir_count = 0;
            while (i < count) {
                const char *entry_path = entries[i].path;
                size_t new_prefix_len = strlen(new_prefix);
                if (strncmp(entry_path, new_prefix, new_prefix_len) == 0 &&
                    (entry_path[new_prefix_len] == '/' || entry_path[new_prefix_len] == '\0')) {
                    subdir_count++;
                    i++;
                } else {
                    break;
                }
            }
            
            // Recursively build the subtree
            ObjectID sub_id = write_tree_level(&entries[subdir_start], subdir_count, depth + 1, new_prefix);
            if (memcmp(&sub_id, &result, sizeof(ObjectID)) == 0 && result.hash[0] == 0) {
                // Error case
                return result;
            }
            
            tree_entry->mode = MODE_DIR;
            tree_entry->hash = sub_id;
            tree.count++;
        }
    }
    
    if (tree.count == 0) {
        return result;  // Empty tree
    }
    
    // Serialize and write the tree
    void *tree_data;
    size_t tree_len;
    if (tree_serialize(&tree, &tree_data, &tree_len) != 0) {
        return result;
    }
    
    if (object_write(OBJ_TREE, tree_data, tree_len, &result) != 0) {
        free(tree_data);
        return result;  // Zero/empty ObjectID indicates error
    }
    
    free(tree_data);
    return result;
}

// Build a tree hierarchy from the current index and write all tree
// objects to the object store.
int tree_from_index(ObjectID *id_out) {
    Index index;
    if (index_load(&index) != 0) {
        return -1;
    }
    
    if (index.count == 0) {
        // Empty index - create an empty tree
        Tree empty_tree = {0};
        void *tree_data;
        size_t tree_len;
        if (tree_serialize(&empty_tree, &tree_data, &tree_len) != 0) {
            return -1;
        }
        
        int rc = object_write(OBJ_TREE, tree_data, tree_len, id_out);
        free(tree_data);
        return rc;
    }
    
    // Sort entries by path
    qsort(index.entries, index.count, sizeof(IndexEntry), compare_index_entries_by_path);
    
    // Build the tree hierarchy
    ObjectID root_id = write_tree_level(index.entries, index.count, 0, "");
    
    // Check if we got a valid result
    if (root_id.hash[0] == 0 && memcmp(&root_id, &index.entries[0].hash, sizeof(ObjectID)) != 0) {
        // Check if it's truly empty or an error
        int all_zero = 1;
        for (int i = 0; i < HASH_SIZE; i++) {
            if (root_id.hash[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (all_zero && index.count > 0) {
            return -1;
        }
    }
    
    *id_out = root_id;
    return 0;
}