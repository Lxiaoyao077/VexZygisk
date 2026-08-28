# VexZygisk

[English](../README.md)

VexZygisk adalah turunan dari Zygisk Next, sebuah implementasi mandiri dari Zygisk, menyediakan dukungan API Zygisk untuk KernelSU.

Tujuannya adalah untuk memodernisasi dan menulis ulang kode sumber sepenuhnya dalam bahasa C, memungkinkan implementasi API Zygisk yang lebih efisien dan cepat dengan lisensi yang lebih permisif dan ramah terhadap FOSS (Free and Open Source Software).

## Mengapa?

Rilisan terbaru dari Zygisk Next tidak bersifat open-source, dengan kode yang sepenuhnya dikendalikan oleh developernya. Hal ini tidak hanya membatasi kemampuan kami untuk berkontribusi pada proyek ini, tetapi juga membuat kode tidak dapat diaudit, yang menjadi masalah utama keamanan karena Zygisk Next adalah modul yang berjalan dengan hak superuser (root), yang memiliki akses ke seluruh sistem.

Meskipun developer Zygisk Next terkenal dan dipercaya dalam komunitas Android, hal ini tidak menjamin bahwa kode tersebut bebas dari bahaya atau kerentanan. Kami (PerformanC) memahami alasan mereka untuk menjaga kode tetap tertutup, tetapi kami memiliki pandangan yang berbeda.

## Keunggulan

- FOSS (Free and Open Source Software) Selamanya.

## Komponen Pendukung

| Alat          | Deskripsi                            |
|---------------|--------------------------------------|
| `Android NDK` | Native Development Kit untuk Android |

### Komponen Pendukung C++

| Ketergantungan | Deskripsi                     |
|----------------|-------------------------------|
| `PLTI`         | Simple PLT Hook untuk Android |
| `CSOLoader`    | Penghubung khusus SOTA Linux  |

## Instalasi

### 1. Pilih file ZIP yang tepat

Pemilihan build/zip sangat penting, karena ini akan menentukan seberapa tersembunyi dan stabil VexZygisk. Namun, ini bukan tugas yang sulit:

- `release`: Direkomendasikan untuk penggunaan normal. Binary lebih optimal, logging minimal.
- `debug`: Untuk keperluan debug. Logging lengkap, tanpa optimasi. Dikarenakan keterangan sebelumnya, **hanya gunakan module ini untuk proses debugging** dan **untuk mendapatkan log ketika menyusun Issue di GitHub**.

Untuk branch, selalu gunakan `main` branch, kecuali diinstruksikan oleh pengembang untuk menggunakan branch lain, atau jika Anda ingin menguji fitur mendatang dan menyadari risikonya.

### 2. Flash file ZIP

Setelah memilih build yang tepat, Anda harus mem-flash-nya menggunakan aplikasi KernelSU. Anda dapat melakukannya dengan masuk ke bagian `Modules` di pengelola root Anda dan memilih zip yang telah diunduh.

Setelah mem-flash, periksa log instalasi untuk memastikan tidak ada kesalahan, dan jika semuanya selesai, Anda dapat me-reboot perangkat Anda

### 3. Verifikasi Instalasi

Setelah reboot, Anda dapat memverifikasi apakah VexZygisk bekerja dengan baik dengan memeriksa deskripsi modul di bagian Modules pada pengelola root Anda. Deskripsi tersebut harus menunjukkan bahwa daemon yang diperlukan sedang berjalan dan akan terlihat seperti ini:
`[Monitor: ✅, VexZygisk 64-bit: ✅] Standalone implementation of Zygisk.`

> [!NOTE]
> Hanya Zygote yang sesuai dengan ABI utama perangkat yang disuntikkan. Pada perangkat 64-bit, Zygote 32-bit sekunder tidak disentuh karena jarang digunakan dan tidak memberikan manfaat; perangkat khusus 32-bit tetap mendapatkan dukungan penuh.

## Terjemahan

Saat ini ada dua cara untuk berkontribusi dalam terjemahan untuk VexZygisk:

- Untuk terjemahan README, Anda dapat membuat file baru di folder `READMEs`, mengikuti konvensi penamaan `README_<bahasa>.md`, di mana `<bahasa>` adalah kode bahasa (misalnya, `README_id-ID.md` untuk Bahasa Indonesia), dan membuka pull request ke `main` branch.
- Untuk terjemahan WebUI VexZygisk, Anda harus berkontribusi terlebih dahulu di [Crowdin](https://crowdin.com/project/rezygisk). Setelah disetujui, ambil file `.json` dari sana dan buka pull request dengan perubahan Anda -- tambahkan file `.json` ke folder `webroot/lang` dan kredit Anda ke file TRANSLATOR.md, dalam urutan alfabet.

## Dukungan

Untuk pertanyaan terkait VexZygisk atau proyek PerformanC lainnya, jangan ragu untuk bergabung dengan salah satu saluran berikut:

Untuk pertanyaan terkait VexZygisk atau proyek PerformanC lainnya, silakan bergabung ke salah satu saluran berikut:

- Saluran Discord: [PerformanC](https://discord.gg/uPveNfTuCJ)
- Saluran Telegram VexZygisk: [@rezygisk](https://t.me/rezygisk)
- Saluran Telegram PerformanC: [@performancorg](https://t.me/performancorg)
- Grup Signal PerformanC: [@performanc](https://signal.group/#CjQKID3SS8N5y4lXj3VjjGxVJnzNsTIuaYZjj3i8UhipAS0gEhAedxPjT5WjbOs6FUuXptcT)

## Kontribusi

Wajib mengikuti [Pedoman Kontribusi](https://github.com/PerformanC/contributing) PerformanC's untuk berkontribusi pada VexZygisk. Sesuai dengan Kebijakan Keamanan, Kode Etik, standar struktur dan format yang berlaku.

## Lisensi

VexZygisk sebagian besar berlisensi di bawah GPL, oleh Dr-TSNG, tetapi juga AGPL 3.0, oleh The PerformanC Organization, untuk kode yang ditulis ulang. Anda dapat juga membaca lebih lanjut di [Open Source Initiative](https://opensource.org/licenses/AGPL-3.0).
