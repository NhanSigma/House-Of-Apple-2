# House-Of-Apple-2
Hướng dẫn kĩ thuật House Of Apple 2 cho anh em mới học pwn.

## 1. Tổng quan sơ lược
Kĩ thuật **House Of Apple 2** là 1 kĩ thuật **FSOP** phải gọi là siêu bá cháy bò chét. Đây là 1 kĩ thuật rất là mạnh nếu bạn có **Use After Free** và có thể leak được. Chỉ cần 2 thứ này thôi là bạn nắm trong tay quyền sinh sát mọi loại bài **Heap**. Ok giờ chúng ta hãy bắt tay vào xem nó là kĩ thuật gì.

## 2. Cách hoạt động của _IO_list_all và House Of Apple 2
Khi 1 chương trình gọi `exit` hoặc bị văng do các lỗi ví dụ như `malloc(): invalid size`, `malloc(): double free`,... thì Glibc sẽ lập tức gọi hàm `_IO_flush_all_lockp()` để quét dọn tất cả các luồng **I/O (File Streams)** đang mở.

Mã code C của nó như sau :

```C
int _IO_flush_all_lockp (void)
{
  ...
  fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
  {
      ...
      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
           || (_IO_vtable_offset (fp) == 0
               && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                                    > fp->_wide_data->_IO_write_base))
           )
          && _IO_OVERFLOW (fp, EOF) == EOF)
      ...
      fp = fp->_chain;
  }
}
```

Chúng ta sẽ có 3 chặng đường chính.

**1. `_IO_flush_all_lockp` -> Kích hoạt `_IO_OVERFLOW`**

**2. `_IO_wfile_overflow` -> Kích hoạt `_IO_wdoallocbuf`**

**3. `_IO_wdoallocbuf` -> Gọi `_wide_vtable->doallocate` ( Nơi ta hijack để gọi `system` )**

### 1. Chặng đầu tiên
Vượt qua lệnh if để gọi `_IO_OVERFLOW (fp, EOF) == EOF)`. Để vượt qua ta cần set `_IO_write_base = 0` và `_IO_write_ptr = 1`. Lúc này `fp->_IO_write_ptr > fp->_IO_write_base` sẽ là 1 > 0 luôn True nên sẽ bypass.

Khi kích hoạt `_IO_OVERFLOW (fp, EOF) == EOF)`, ta đã ghi đè `vtable` thành `_IO_wfile_jumps` nên hàm được gọi thực chất là `_IO_wfile_overflow`. Lí do ?

Khi `_IO_OVERFLOW (fp, EOF) == EOF)`, nó sẽ gọi `(fp->vtable->__overflow) (fp, EOF);`. Mà trong bảng `vtable` nằm ở offset `0xd8` của chunk `fp`

```C
struct _IO_jump_t {
    size_t __dummy;
    size_t __dummy2;
    _IO_finish_t __finish;
    _IO_overflow_t __overflow;  <--- Vị trí hàm Glibc cần gọi
    _IO_underflow_t __underflow;
    // ...
};
```

Khi ta đổi thành `_IO_wfile_jumps`, nó sẽ gọi vẫn ở vị trí đó nhưng mà ở hàm khác

```C
const struct _IO_jump_t _IO_wfile_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_new_file_finish),
  JUMP_INIT(overflow, _IO_wfile_overflow),  <--- Đích đến!
  JUMP_INIT(underflow, _IO_wfile_underflow),
  // ...
};
```

### 2. Chặng thứ hai : Đi qua `_IO_wfile_overflow`

Khi glibc nhảy vào `_IO_wfile_overflow`, ta đã vượt qua được cơ chế bảo vệ `vtable` của glibc `(_IO_vtable_check)`, bởi vì `_IO_wfile_jumps` là một `vtable` hoàn toàn hợp lệ nằm sẵn trong vùng nhớ read-only của Libc.

```C
wint_t _IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* Kiểm tra 1: File có bị cấm ghi không? */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  ...
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_wide_data->_IO_write_base == NULL)
    {
      ...
      if (f->_wide_data->_IO_write_base == NULL)
        {
          _IO_wdoallocbuf (f); /* Đích đến của chúng ta! */
        }
    }
    ...
}
```

Giờ ta cần ép luồng thực thi `_IO_wdoallocbuf (f)`. Đầu tiên là vượt qua nhánh cấm ghi bằng cách ta set `_flags` ( ở offset 0x00 ) là chuỗi `  sh;`. Chuỗi này khi dịch sang hex là 0x3b687320 không chứa bit `_IO_NO_WRITES` ( 0x8 ).

Để thỏa mãn điều kiện tiếp theo, ta sẽ dùng kỹ thuật **Overlapping** ( trỏ `_wide_data` về lại chính đầu của `_IO_FILE fake`). Do đó, `f->_wide_data->_IO_write_base` thực chất sẽ trỏ vào vùng toàn byte null ( `_IO_FILE fake + 0x20:0x28` ), làm cho điều kiện == NULL trở thành True. `_IO_wdoallocbuf(f)` được gọi.

## 3. Chặng 3 : Kích nổ Shell tại `_IO_wdoallocbuf`

Đây là chặng cuối cùng. Hàm `_IO_wdoallocbuf` có nhiệm vụ cấp phát một buffer mới cho file stream nếu nó chưa có.

```C
void _IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;

  if (!(fp->_flags & _IO_UNBUFFERED) || fp->_mode > 0)
    if (WDOALLOCATE (fp) != EOF)
      ...
}
```

```C
#define WDOALLOCATE(fp) \
  (*(struct _IO_jump_t *) fp->_wide_data->_wide_vtable)->doallocate (fp)
```

Để bypass if, ta cần set `_mode` = 1 thứ mà ta đã setup rồi. Lúc này nó sẽ gọi `WDOALLOCATE(fp)`.

Bên trong `WDOALLOCATE(fp)`, nó sẽ tìm con trỏ `_wide_vtable` bên trong `_wide_data` của chúng ta, lấy ra hàm ở offset của `doallocate` ( offset 0x68 ) và thực thi nó với tham số truyền vào là chính fp ( con trỏ của fake chunk ). Suy ra `(fp->_wide_data->_wide_vtable)->doallocate (fp)` biến thành:
`system(fp)`. Mà ta đã setup `fp` thành `  sh;` ngay từ đầu nên nó sẽ thực thi `system(sh)`.

### Tóm tắt :
Bằng cách sử dụng `_IO_wfile_jumps`, **House of Apple 2** chuyển hướng quyền kiểm soát sang cấu trúc `_wide_data`. Vì `_wide_data->_wide_vtable` không hề bị glibc kiểm tra tính hợp lệ ( như cơ chế bảo vệ của `vtable` thông thường ), ta có thể thoải mái tạo một `vtable` giả mạo và trỏ con trỏ hàm `doallocate` về `system`.

Bảng phân tích offset chi tiết :

| Offset | Trường (Field) | Giá trị cần ghi đè | Mục đích (Bypass) |
| :--- | :--- | :--- | :--- |
| `0x00` | `_flags` | `b"  sh;"` | Sẽ được truyền vào thanh ghi `RDI` ở cuối chuỗi ROP. Chuỗi này không chứa bit `_IO_NO_WRITES` nên vượt qua được check của `_IO_wfile_overflow`. |
| `0x20` | `_IO_write_base` | `0` | Kết hợp với `_write_ptr` để tạo điều kiện `_write_ptr > _write_base` (1 > 0). |
| `0x28` | `_IO_write_ptr` | `1` | Giúp kích hoạt hàm `_IO_OVERFLOW` khi glibc thực hiện flush. |
| `0x88` | `_lock` | `base_addr + 0x160` | Phải trỏ tới một vùng nhớ có giá trị `0x0` (có thể tận dụng không gian thừa của chunk) để tránh lỗi deadlock khi Glibc cố gắng khóa file. |
| `0xa0` | `_wide_data` | `base_addr` | Trỏ về đầu chunk. Kỹ thuật này ép Glibc đọc cấu trúc `_wide_data` giả ngay trên phần thân của `_IO_FILE` để tiết kiệm byte. |
| `0xc0` | `_mode` | `1` | Thỏa mãn điều kiện `_mode > 0` để Glibc đi vào hàm `_IO_wdoallocbuf`. |
| `0xd8` | `vtable` | `&_IO_wfile_jumps` | Bảng vtable hợp lệ của Glibc, dùng để bypass cơ chế `_IO_vtable_check`. |
| `0xe0` | `_wide_vtable` | `base_addr + 0xe8` | Nằm tại offset `0xe0` của `_wide_data`. Trỏ tới bảng vtable giả thứ hai nằm ngay bên dưới nó. |
| `0x150`| `doallocate` | `&system` | Nằm tại offset `0x68` của `_wide_vtable`. Đích đến cuối cùng nơi shell được thực thi. |

Từ đây ta có thể chia ra được 2 Memory Layout. 

### Memory Layout no Overlapping ( Linear Layout )

```md
=================[ CHUNK GIẢ MẠO CƠ BẢN ]=================

[1. VÙNG _IO_FILE ] (Bắt đầu tại base_addr)
0x000 +------------------------------------+ 
      | _flags ("  sh;")                   | 
      +------------------------------------+
      | ...                                |
0x020 | _IO_write_base (0)                 | > Bypass _IO_OVERFLOW
0x028 | _IO_write_ptr  (1)                 | 
      +------------------------------------+
      | ...                                |
0x088 | _lock (Trỏ tới vùng NULL: +0x250)  | > Bypass deadlock
      +------------------------------------+
      | ...                                |
0x0a0 | _wide_data (Trỏ tới base_addr+0xe0)| > Trỏ tới vùng 2 bên dưới
      +------------------------------------+
      | ...                                |
0x0c0 | _mode (1)                          | > Bypass wdoallocbuf
      +------------------------------------+
      | ...                                |
0x0d8 | vtable (&_IO_wfile_jumps)          | > Bypass vtable check
      +------------------------------------+

[2. VÙNG _wide_data ] (Bắt đầu tại base_addr + 0xe0)
0x0e0 +------------------------------------+
      | ...                                |
0x0f8 | _IO_write_base (0)                 | > Offset 0x18 của wide_data
      +------------------------------------+
      | ...                                |
0x110 | _IO_buf_base (0)                   | > Offset 0x30 của wide_data
      +------------------------------------+
      | ...                                |
0x1c0 | _wide_vtable (Trỏ tới base + 0x1c8)| > Trỏ tới vùng 3 bên dưới
      +------------------------------------+

[3. VÙNG _wide_vtable ] (Bắt đầu tại base_addr + 0x1c8)
0x1c8 +------------------------------------+
      | ...                                |
0x230 | doallocate (&system)               | > Offset 0x68 của _wide_vtable
      +------------------------------------+
```

### Memory Layout Overlapping

```md
======================[ CHUNK GIẢ MẠO OVERLAPPING ]======================
> _wide_data = base_addr 

Offset | Lăng kính struct _IO_FILE       | Lăng kính struct _wide_data
-------|---------------------------------|-------------------------------
0x000  | _flags ("  sh;")                | _IO_read_ptr
       |                                 |
       | padding (Tất cả là NULL)        |
       |                                 |
0x018  | _IO_read_base (NULL)            | _IO_write_base (NULL) <=== Bypass 1
0x020  | _IO_write_base (0) <=== Bypass  | _IO_write_ptr
0x028  | _IO_write_ptr (1)  <=== Bypass  | _IO_buf_end
0x030  | _IO_buf_base (NULL)             | _IO_buf_base (NULL)   <=== Bypass 2
       |                                 |
       | padding (Tất cả là NULL)        |
       |                                 |
0x088  | _lock (Trỏ tới offset 0x160)    | _wide_data (Vô hại)
       |                                 |
       | padding (Tất cả là NULL)        |
       |                                 |
0x0a0  | _wide_data (Trỏ về 0x000)       | _freeres_buf (Vô hại)
       |                                 |
       | padding (Tất cả là NULL)        |
       |                                 |
0x0c0  | _mode (1)          <=== Bypass  | _offset (Vô hại)
       |                                 |
       | padding (Tất cả là NULL)        |
       |                                 |
0x0d8  | vtable (&_IO_wfile_jumps)       | [Biến này không thuộc _wide_data]
-------|---------------------------------|-------------------------------
[ HẾT struct _IO_FILE - BẮT ĐẦU VÙNG CỦA RIÊNG _wide_data ]
-------|---------------------------------|-------------------------------
0x0e0  | [Không còn thuộc _IO_FILE]      | _wide_vtable (Trỏ tới 0x0e8)
       |                                 |
0x0e8  | ... Bắt đầu _wide_vtable ...    |
       |                                 |
0x150  | ... Điểm chèn &system ...       | doallocate (Nằm tại 0xe8 + 0x68)
       |                                 |
0x160  | ... Vùng chứa NULL ...          | <=== Đích đến của biến _lock
```

Đây chỉ là 1 phiên bản tối ưu và dễ nhìn nhất, chúng ta sẽ còn 1 phiên bản khác nữa đó là hay vì tại vị trí `_wide_vtable` ta cho nó trỏ vào `base + 0xe8` thì ta sẽ trỏ nó vào `base + 0x28`

```md
=================[ EXTREME OVERLAPPING PAYLOAD (0xe8 Bytes) ]=================

Offset | Trường bị ghi đè            | Giải thích logic
-------|-----------------------------|----------------------------------------
0x000  | _flags ("  sh;")            | Chuỗi lệnh thực thi system("  sh;")
       | padding (NULL)              |
0x018  | (NULL)                      | = _wide_data->_IO_write_base (Bypass 1)
0x020  | _IO_write_base (0)          | Bypass _IO_OVERFLOW
0x028  | _IO_write_ptr (1)           | Bypass _IO_OVERFLOW
0x030  | (NULL)                      | = _wide_data->_IO_buf_base   (Bypass 2)
0x038  | (NULL)                      | <--- Đích đến của biến _lock 
       | padding (NULL)              |
0x088  | _lock                       | ---> Trỏ về (base_addr + 0x38)
0x090  | _offset (&system)           | <=== CHÍNH LÀ ĐIỂM KÍCH NỔ doallocate!
       | padding (NULL)              | 
0x0a0  | _wide_data (base_addr)      | ---> Trỏ về chính đầu chunk (0x000)
       | padding (NULL)              |
0x0c0  | _mode (1)                   | Bypass _IO_wdoallocbuf
       | padding (NULL)              |
0x0d8  | vtable (&_IO_wfile_jumps)   | Bypass _IO_vtable_check
0x0e0  | _wide_vtable                | ---> Trỏ về (base_addr + 0x28) 
-------+-----------------------------+----------------------------------------
```

Đây là 1 kĩ thuật mới ép độ lớn từ 352 byte xuống còn 232 byte. Theo công thức thì `doallocbuf` luôn cách `_wide_vtable` 0x68, vậy suy ra thì `system` sẽ nằm ở vị trí 0x90. Mà tại vị trí này của `_IO_FILE` thì đó là trường `_offset`, chỉ dùng để gọi `seek()` nên không ảnh hưởng gì. Bên cạnh đó `_lock` ở 0x88 cần 1 vùng null nên ta sẽ trỏ nó vào `base + 0x38`.

Ok chúng ta đã đi qua 3 Memory Layout rồi, việc tận dụng nó và sử dụng sao là việc các bạn. Mình có bỏ 1 bài mẫu trong đây, các bạn có thể qua đọc thử và hiểu cách áp dụng của nó nha.

## Nguồn tài liệu

https://www.slideshare.net/slideshow/play-with-file-structure-yet-another-binary-exploit-technique/81635564
