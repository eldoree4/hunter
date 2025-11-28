# 🛡️ Bug Hunter Advanced v5.0 (Enterprise Edition)
**Creator: El Doree**

Alat pengujian keamanan berbasis Bash yang canggih dan multi-threaded. Dirancang untuk melampaui scan status kode dasar, berfokus pada Analisis Perilaku Respons melalui Smart Baseline Caching dan Anomaly Detection untuk mengungkap kerentanan tersembunyi (blind dan time-based).

---

## 🚨 Peringatan Etika & Hukum

**ALAT INI HANYA UNTUK TUJUAN PENGUJIAN ETIS DAN PENDIDIKAN.**

**PENGGUNA BERTANGGUNG JAWAB PENUH** atas setiap kerusakan atau konsekuensi hukum yang timbul dari penyalahgunaan alat ini.

---

## ⚙️ Fitur Unggulan Enterprise (v5.0)

### 🧠 Smart Baseline Caching
Melakukan pra-pemindaian untuk setiap URL guna mendapatkan data ukuran tubuh dan waktu respons normal.

### ⏱️ Time Delta Anomaly
Mendeteksi respons yang jauh lebih lambat dari waktu baseline. Indikator potensi Blind Time-Based Injection.

### 📏 Size Delta Anomaly
Mendeteksi respons yang memiliki perubahan ukuran signifikan dari baseline. Indikator potensi Blind SSRF atau Error Injection.

### 🗂️ Manajemen State
Mampu menyimpan dan memuat semua pengaturan (Threads, Proxy, Thresholds, Headers Kustom) ke file `bh_config.cfg`.

---

## 🛠️ Instalasi dan Persyaratan

### Persyaratan Wajib
Bash, cURL, xargs, md5sum, dan bc (Basic Calculator).

### Instalasi bc (Termux)
Jalankan: `pkg update` dan `pkg install bc`

### Setup Awal
1. `chmod +x hunter.sh`
2. `./hunter.sh`

---

## 💻 Panduan Penggunaan Detail (Langkah-Langkah)

### Langkah 1: Persiapan File Input
Buat file: 
- `targets.txt` (Daftar URL per baris) 
- `payloads.txt` (Daftar payload per baris)

### Langkah 2: Konfigurasi Threshold
1. Di Menu Utama, pilih **4. Konfigurasi Lanjutan**
2. Atur **F (Size Delta)** dan **G (Time Delta Factor)**

### Langkah 3: Konfigurasi Fuzzing
1. Pilih **K. Konfigurasi Fuzzing Header**
2. Atur Header Target (cth: `Client-IP`) dan File Payload (cth: `payloads.txt`)
3. Pilih **N. Simpan Konfigurasi**

### Langkah 4: Menjalankan Scan
1. Di Menu Utama, pilih **3. Scan dari List URL dengan Advanced Fuzzing**
2. Masukkan nama file target (cth: `targets.txt`)

### Proses Otomatis
Skrip akan melakukan dua fase: 
- **Pre-Scan Baseline** 
- **Fuzzing & Analisis** (mencetak alert Delta secara real-time)

---

## 📊 Hasil dan Output File

### Akses Hasil
Setelah selesai, pilih **5. Lihat Hasil & Log** di Menu Utama, atau akses folder `results_YYYYMMDD_HHMMSS`

### Daftar Bug/Anomali
`vulnerability_alerts.txt`: Fokus Utama. Berisi semua alert TIME DELAY, SIZE DELTA, dan GREP VULN.

### Daftar URL 200 OK
`200_ok.txt`: Berisi daftar URL yang merespons 200 OK dan tidak memicu anomali.

### Akses Data Mentah
`full_responses/`: Menyimpan Header dan Body lengkap untuk analisis mendalam.
