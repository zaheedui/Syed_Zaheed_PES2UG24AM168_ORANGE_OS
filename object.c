// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // Step 1: Build the full object: header ("blob 16\0") + data
    const char *type_str;
    switch (type) {
        case OBJ_BLOB:   type_str = "blob"; break;
        case OBJ_TREE:   type_str = "tree"; break;
        case OBJ_COMMIT: type_str = "commit"; break;
        default: return -1;
    }

    // Build header string
    char header[256];
    snprintf(header, sizeof(header), "%s %lu", type_str, (unsigned long)len);
    size_t header_len = strlen(header);

    // Create full object: header + '\0' + data
    size_t full_len = header_len + 1 + len;
    void *full_obj = malloc(full_len);
    if (!full_obj) return -1;

    memcpy(full_obj, header, header_len);
    ((char *)full_obj)[header_len] = '\0';
    if (len > 0) memcpy((char *)full_obj + header_len + 1, data, len);

    // Step 2: Compute SHA-256 hash of the FULL object
    compute_hash(full_obj, full_len, id_out);

    // Step 3: Check if object already exists (deduplication)
    if (object_exists(id_out)) {
        free(full_obj);
        return 0;
    }

    // Step 4: Create shard directory if it doesn't exist
    char shard_dir[512];
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(shard_dir, 0755);

    // Step 5: Write to a temporary file
    char path[512];
    object_path(id_out, path, sizeof(path));
    
    char tmp_path[520];
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path) >= (int)sizeof(tmp_path)) {
        free(full_obj);
        return -1;
    }

    int fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        free(full_obj);
        return -1;
    }

    if (write(fd, full_obj, full_len) != (ssize_t)full_len) {
        close(fd);
        unlink(tmp_path);
        free(full_obj);
        return -1;
    }

    // Step 6: fsync() the temporary file to ensure data reaches disk
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp_path);
        free(full_obj);
        return -1;
    }
    close(fd);

    // Step 7: rename() the temp file to the final path (atomic on POSIX)
    if (rename(tmp_path, path) != 0) {
        free(full_obj);
        return -1;
    }

    // Step 8: fsync() the shard directory to persist the rename
    fd = open(shard_dir, O_RDONLY);
    if (fd >= 0) {
        fsync(fd);
        close(fd);
    }

    free(full_obj);
    return 0;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    object_path(id, path, sizeof(path));

    // Step 1: Open and read the entire file
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    // Read file into memory
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    if (file_size < 0) {
        fclose(f);
        return -1;
    }
    fseek(f, 0, SEEK_SET);

    void *file_data = malloc(file_size);
    if (!file_data) {
        fclose(f);
        return -1;
    }

    if (fread(file_data, 1, file_size, f) != (size_t)file_size) {
        free(file_data);
        fclose(f);
        return -1;
    }
    fclose(f);

    // Step 2 & 3: Parse the header and verify integrity
    // Find the null terminator that separates header and data
    void *null_ptr = memchr(file_data, '\0', file_size);
    if (!null_ptr) {
        free(file_data);
        return -1;
    }

    size_t header_len = (char *)null_ptr - (char *)file_data;
    char header_str[256];
    if (header_len >= sizeof(header_str)) {
        free(file_data);
        return -1;
    }
    memcpy(header_str, file_data, header_len);
    header_str[header_len] = '\0';

    // Parse type and size from header
    char type_name[32];
    size_t parsed_size;
    if (sscanf(header_str, "%31s %zu", type_name, &parsed_size) != 2) {
        free(file_data);
        return -1;
    }

    // Map type string to ObjectType
    ObjectType type;
    if (strcmp(type_name, "blob") == 0)       type = OBJ_BLOB;
    else if (strcmp(type_name, "tree") == 0)  type = OBJ_TREE;
    else if (strcmp(type_name, "commit") == 0) type = OBJ_COMMIT;
    else {
        free(file_data);
        return -1;
    }

    // Verify that the parsed size matches actual data
    size_t data_len = file_size - header_len - 1;
    if (data_len != parsed_size) {
        free(file_data);
        return -1;
    }

    // Verify integrity: recompute SHA-256 and compare
    ObjectID computed_id;
    compute_hash(file_data, file_size, &computed_id);
    if (memcmp(&computed_id, id, sizeof(ObjectID)) != 0) {
        free(file_data);
        return -1;  // Hash mismatch - corruption detected
    }

    // Step 5 & 6: Extract data portion and return it
    void *data_out_buf = malloc(data_len);
    if (!data_out_buf) {
        free(file_data);
        return -1;
    }
    if (data_len > 0) {
        memcpy(data_out_buf, (char *)file_data + header_len + 1, data_len);
    }

    *type_out = type;
    *data_out = data_out_buf;
    *len_out = data_len;

    free(file_data);
    return 0;
}
