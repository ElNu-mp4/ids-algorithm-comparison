# IDS Algorithm Comparison

Implementasi dan benchmarking perbandingan tiga algoritma pattern matching untuk Signature-Based Intrusion Detection System (IDS):

- **Brute Force** — naive string matching O(n×m)
- **Backtracking** — regex berbasis PCRE via modul `re` Python
- **Bloom Filter** — struktur probabilistik dengan lookup O(k)

> Dibuat untuk makalah: *"Perbandingan Algoritma Brute Force, Backtracking, dan Bloom Filter dalam Optimasi Deteksi Pola Serangan Jaringan pada Signature-Based IDS"*
> Elang Nukmianolo – 24060123130049, Departemen Informatika, Universitas Diponegoro

---

## Struktur Proyek

```
ids-algorithm-comparison/
├── ids_algorithm_comparison.py   # Kode utama (semua algoritma + benchmark)
└── README.md
```

---

## Requirements

- Python 3.11+
- Library:

```bash
pip install bitarray mmh3
```

| Library    | Kegunaan                              |
|------------|---------------------------------------|
| `bitarray` | Bit array efisien untuk Bloom Filter  |
| `mmh3`     | MurmurHash3 sebagai fungsi hash       |

---

## Cara Menjalankan

```bash
python ids_algorithm_comparison.py
```

Output yang dihasilkan:

- **Tabel II** — Throughput (paket/detik) vs jumlah signature (10–10.000)
- **Tabel III** — Waktu pencocokan pada payload adversarial `(a+)+$`
- **Tabel IV** — Kalibrasi parameter Bloom Filter (target FPR 10%, 1%, 0.1%, 0.01%)
- **Tabel V** — Perbandingan memori dan throughput pada 10.000 signature

---

## Penjelasan Singkat Tiap Komponen

### BruteForceIDS
Mencocokkan setiap signature secara linear terhadap payload karakter per karakter. Tidak ada preprocessing. Kompleksitas total O(s×n×m) per paket dengan s = jumlah signature.

### BacktrackingIDS
Menggunakan `re.compile()` untuk mengompilasi signature menjadi objek regex. Mendukung uji adversarial dengan pola bersarang seperti `(a+)+$` yang memicu kompleksitas eksponensial O(2ⁿ).

### BloomFilter / BloomFilterIDS
Menghitung ukuran bit array `m` dan jumlah fungsi hash `k` secara otomatis dari jumlah elemen `n` dan target false positive rate. Menggunakan MurmurHash3 dengan seed berbeda untuk tiap fungsi hash.

```python
# Contoh penggunaan manual
bf = BloomFilter(n=10000, fp_rate=0.01)
bf.add("sig_serangan")
print("sig_serangan" in bf)  # True
```

### Dataset Generator
Karena penelitian ini bersifat simulasi, dataset dibuat secara programatik:

```python
signatures = generate_signatures(n=1000, avg_len=20)
packets    = generate_traffic(n_packets=5000, signatures=signatures, attack_ratio=0.25)
```

`attack_ratio=0.25` berarti 25% paket mengandung signature serangan (sesuai distribusi di makalah: SQL injection, XSS, port scan, FTP brute-force masing-masing 25%).

### Benchmark Framework
```python
result = benchmark(ids_instance, packets, label="Brute Force")
# result berisi: throughput, waktu per paket, memori peak
```

Menggunakan `time.perf_counter()` untuk presisi tinggi dan `tracemalloc` untuk pengukuran memori.

---

## Hasil Eksperimen (Ringkasan)

| Algoritma    | 10 sig (pkt/s) | 10.000 sig (pkt/s) | Adversarial n=28 |
|--------------|----------------|--------------------|------------------|
| Brute Force  | ~12.450        | ~14                | Tidak terpengaruh |
| Backtracking | ~8.320         | ~11                | ~9.847 ms        |
| Bloom Filter | ~187.300       | ~171.200           | Tidak terpengaruh |

Bloom Filter unggul **12.200×** dibanding Brute Force pada 10.000 signature.

---

## Catatan Dataset

Kode ini menggunakan **dataset simulasi** yang cukup untuk keperluan perbandingan algoritma. Untuk validasi lebih lanjut dengan data nyata, dapat digunakan:

- [Snort Community Rules](https://www.snort.org/downloads) — signature database nyata
- [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) — traffic dataset berlabel
- [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) — traffic dataset modern

---

## Lisensi

Kode ini dibuat untuk keperluan akademis. Bebas digunakan dan dimodifikasi dengan mencantumkan sumber.
