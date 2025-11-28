Tentu, ini adalah file `README.md` yang disajikan dalam bentuk tabel dengan dua kolom (`Key` dan `Value`) agar mudah bagi Anda untuk disalin dan ditempelkan ke dalam dokumen Anda.

| Key | Value |
| :--- | :--- |
| **Filename** | `README.md` |
| **Heading 1** | \# 🛡️ Bug Hunter Advanced v5.0 (Enterprise Edition) |
| **Subtitle 1** | **Creator:** El Doree | **Versi:** 5.0 (Enterprise Edition) |
| **Deskripsi Utama** | Alat pengujian keamanan berbasis Bash yang canggih dan *multi-threaded*. Dirancang untuk melampaui *scan* status kode dasar, berfokus pada **Analisis Perilaku Respons** melalui **Smart Baseline Caching** dan **Anomaly Detection** untuk mengungkap kerentanan tersembunyi (*blind* dan *time-based*). |
| **---** | --- |
| **Heading 2** | \#\# 🚨 Peringatan Etika & Hukum |
| **Peringatan 1** | **ALAT INI HANYA UNTUK TUJUAN PENGUJIAN ETIS DAN PENDIDIKAN.** |
| **Peringatan 2** | **PENGGUNA BERTANGGUNG JAWAB PENUH** atas setiap kerusakan atau konsekuensi hukum yang timbul dari penyalahgunaan alat ini. |
| **---** | --- |
| **Heading 3** | \#\# ⚙️ Fitur Unggulan Enterprise (v5.0) |
| **Fitur: Baseline Caching** | **🧠 Smart Baseline Caching:** Melakukan pra-pemindaian untuk setiap URL guna mendapatkan data **ukuran tubuh** dan **waktu respons** normal. |
| **Fitur: Time Delta** | **⏱️ Time Delta Anomaly:** Mendeteksi respons yang **jauh lebih lambat** dari waktu baseline. Indikator potensi *Blind Time-Based Injection*. |
| **Fitur: Size Delta** | **📏 Size Delta Anomaly:** Mendeteksi respons yang memiliki **perubahan ukuran signifikan** dari baseline. Indikator potensi *Blind SSRF* atau *Error Injection*. |
| **Fitur: State Management** | **Manajemen State:** Mampu **menyimpan** dan **memuat** semua pengaturan (Threads, Proxy, Thresholds, Headers Kustom) ke file `bh_config.cfg`. |
| **---** | --- |
| **Heading 4** | \#\# 🛠️ Instalasi dan Persyaratan |
| **Persyaratan Wajib** | Bash, cURL, xargs, md5sum, dan **bc (Basic Calculator)**. |
| **Instalasi `bc` (Termux)** | Jalankan: `pkg update` dan `pkg install bc` |
| **Setup Awal** | 1. `chmod +x bug_hunter_advanced.sh` <br> 2. `./bug_hunter_advanced.sh` |
| **---** | --- |
| **Heading 5** | \#\# 💻 Panduan Penggunaan Detail (Langkah-Langkah) |
| **Langkah 1: Persiapan File Input** | Buat file: **`targets.txt`** (Daftar URL per baris) dan **`payloads.txt`** (Daftar *payload* per baris). |
| **Langkah 2: Konfigurasi Threshold** | 1. Di **Menu Utama**, pilih **4. Konfigurasi Lanjutan**. <br> 2. Atur **F (Size Delta)** dan **G (Time Delta Factor)**. |
| **Langkah 2: Konfigurasi Fuzzing** | 3. Pilih **K. Konfigurasi Fuzzing Header**. <br> 4. Atur Header Target (cth: `Client-IP`) dan File Payload (cth: `payloads.txt`). <br> 5. Pilih **N. Simpan Konfigurasi**. |
| **Langkah 3: Menjalankan Scan** | 1. Di **Menu Utama**, pilih **3. Scan dari List URL dengan Advanced Fuzzing**. <br> 2. Masukkan nama file target (cth: `targets.txt`). |
| **Proses Otomatis** | Skrip akan melakukan dua fase: **Pre-Scan Baseline** dan **Fuzzing & Analisis** (mencetak alert Delta secara *real-time*). |
| **---** | --- |
| **Heading 6** | \#\# 📊 Hasil dan Output File |
| **Akses Hasil** | Setelah selesai, pilih **5. Lihat Hasil & Log** di Menu Utama, atau akses folder `results_YYYYMMDD_HHMMSS`. |
| **Daftar Bug/Anomali** | `vulnerability_alerts.txt`: **Fokus Utama.** Berisi semua alert TIME DELAY, SIZE DELTA, dan GREP VULN. |
| **Daftar URL 200 OK** | `200_ok.txt`: Berisi daftar URL yang merespons **200 OK** dan tidak memicu anomali. |
| **Akses Data Mentah** | `full_responses/`: Menyimpan *Header* dan *Body* lengkap untuk analisis mendalam. |
