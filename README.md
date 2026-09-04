![Screenshot](https://raw.githubusercontent.com/neveerlabs/data-center/main/screenshot.jpg)

# Data Center

Aplikasi penyimpan data penting (akun dan API) secara lokal dan terenkripsi

## Deskripsi

Data Center adalah tool CLI berbasis terminal (curses) untuk menyimpan dan mengelola data akun serta API key secara aman. Semua data disimpan dalam satu file terenkripsi (AES-GCM) di direktori home pengguna. Tidak ada data yang dikirim ke server mana pun

## Fitur

- Tambah, edit, hapus, dan lihat data akun atau API
- Kategorisasi otomatis (Account / API)
- Enkripsi AES-256-GCM dengan key derivasi PBKDF2
- File data sensitif disimpan di `~/.data-center/`
- Antarmuka terminal sederhana menggunakan curses
- Sessions setiap 5 menit, dan akan diminta password secara ulang setelah sesi habis
- Pencarian data dengan `title` / `name` sebagai kata kunci di bagian update, delete dan view

## Instalasi

### Dependensi

- Python 3.6+
- `pycryptodome`

Install dependensi:

```bash
pip install pycryptodome
```

### Penggunaan

- Run script
```bash
python akun.py
```
- Saat pertama kali digunakan, akan diminta membuat password baru. password ini digunakan untuk mengenkripsi dan mendekripsi data
- setelah login, akan masuk ke menu utama. navigasi menggunakan tombol panah (kiri / kanan) dan enter untuk 

## File yang Dibuat Otomatis

Semua file disimpan di direktori `~/.data-center/`:

| File          | Deskripsi                                     |
|---------------|-----------------------------------------------|
| `.password`   | Hash password (SHA-256 + salt)                |
| `.salt`       | Salt acak untuk derivasi key                  |
| `.data.enc`   | File data terenkripsi (AES-GCM)               |

`data.enc` berisi seluruh data yang disimpan. Isinya sudah terenkripsi, sehingga tidak bisa dibaca secara langsung

## Keamanan

- Password diverifikasi menggunakan hash SHA-256 dengan salt unik.
- Key enkripsi diturunkan dari password dengan PBKDF2 (100.000 iterasi).
- Data dienkripsi menggunakan AES-256-GCM (autentikasi dan enkripsi).
- File `.password`, `.salt`, dan `.data.enc` bersifat sensitif dan harus dijaga.

## Lisensi

Proyek ini dilisensikan di bawah [Apache License 2.0](LICENSE).
