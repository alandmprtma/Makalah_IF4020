# Makalah IF4020 - Dilithium Post-Quantum Digital Signature

**Implementation and Evaluation of the Dilithium Algorithm as a Post-Quantum Digital Signature Scheme**

## 📔 Deskripsi Program

**Dilithium** adalah program simulasi dan evaluasi algoritma tanda tangan digital post-kuantum **CRYSTALS-Dilithium** sesuai standar NIST. Program ini dibuat untuk Makalah IF4020 Kriptografi dengan mengimplementasikan:

- **CRYSTALS-Dilithium** — Skema tanda tangan digital berbasis lattice (NIST PQC)
- **Key Generation, Signing, Verification** — Proses pembuatan kunci, penandatanganan, dan verifikasi tanda tangan
- **Tiga Level Keamanan** — Mendukung Dilithium2, Dilithium3, dan Dilithium5
- **Analisis Performa & Ukuran** — Pengujian kecepatan dan ukuran kunci/tanda tangan, serta perbandingan dengan algoritma klasik dan post-quantum lain
- **Python murni** — Implementasi edukatif, mudah dipahami, dan dapat dijalankan tanpa library eksternal khusus

## 📟 Tech Stack

- **Bahasa:** Python 3.8+
- **Library:** NumPy (operasi polinomial dan matriks)
- **Testing & Evaluasi:** Script Python (test/run_all_tests.py)

## 🛠️ Dependensi Utama

- numpy
- (opsional) pickle (untuk serialisasi saat analisis ukuran)
- Standar library Python: hashlib, secrets, time, sys, os

## ⚙️ Cara Menjalankan Program di Lokal

### 1. Clone repository

```bash
git clone https://github.com/alandmprtma/Makalah_IF4020.git
cd Makalah_IF4020
```

### 2. Install dependensi

Pastikan Python 3.8+ dan pip sudah terpasang. Install dependensi utama:

```bash
pip install -r requirements.txt
```

### 3. Jalankan pengujian Dilithium

Masuk ke folder `test/` dan jalankan skrip pengujian:

```bash
cd test
python run_all_tests.py
```

### 4. Lihat hasil

Hasil pengujian dan evaluasi akan tersimpan di file `test/hasil_testing_dilithium.txt`.

## 📇 Contributors

| Nama                       | NIM      |
| -------------------------- | -------- |
| Aland Mulia Pratama        | 13522124 |
