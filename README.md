# Bài tập CMC

## Bài 1
#### Các file:
- **`file_info.cc`** : Check các thông tin cơ bản của 1 PE file

- **`exported_function.cc`** và **`imported_function.cc`**: Check các hàm được export và import vào PE file

#### Usage:
- Compile các file **`.cc`** ra file **`.exe`** : **`g++ \<file_name>.cc -o <file_name>.exe`**

- Chạy : **`<file_name>.exe <targer_PEfile_name>.exe`**

## Bài 2
#### Các file:
- **`inject_32bit.c`** và **`inject_64bit.c`** : Inject shellcode vào 1 PE file 32bit hoặc 64bit 

- **`inject_all.c`**: Inject shellcode vào tất cả các PE file 32bit trong cùng 1 folder (không dùng được cho các PE file 64bit, sẽ báo không inject được vào PE file 64bit)

- **`inject_all_32_64.c`**: Inject shellcode vào tất cả các PE file 32bit hoặc 64bit trong cùng 1 folder

- **`inject.s`** và **`inject_all.s`**: ***(Assembly MASM32)*** Inject shellcode vào 1 PE file 32bit và Inject shellcode vào tất cả các PE file 32bit trong cùng 1 folder

#### Usage:
- Compile các file **`.cc`** ra file **`.exe`** ở dạng 32bit: **`gcc -m32 -Wall -O2 \<file_name>.cc -o <file_name>.exe -luser32`**

- Chạy : **`<file_name>.exe <targer_PEfile_name>.exe`**

## Bài 3
