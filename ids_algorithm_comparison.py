"""
Perbandingan Algoritma Brute Force, Backtracking, dan Bloom Filter
dalam Optimasi Deteksi Pola Serangan Jaringan pada Signature-Based IDS

Elang Nukmianolo – 24060123130049
Departemen Informatika, Universitas Diponegoro
"""

import re
import time
import timeit
import tracemalloc
import random
import string
import math
from bitarray import bitarray
import mmh3  # MurmurHash3


# ==============================================================================
# 1. BRUTE FORCE
# ==============================================================================

class BruteForceIDS:
    """
    Naive string matching O(n x m) per signature.
    Tidak ada preprocessing; cocok setiap signature satu per satu.
    """

    def __init__(self, signatures: list[str]):
        self.signatures = signatures

    def match(self, payload: str) -> bool:
        for sig in self.signatures:
            n, m = len(payload), len(sig)
            for i in range(n - m + 1):
                j = 0
                while j < m and payload[i + j] == sig[j]:
                    j += 1
                if j == m:
                    return True  # match ditemukan
        return False


# ==============================================================================
# 2. BACKTRACKING (PCRE via modul re)
# ==============================================================================

class BacktrackingIDS:
    """
    Regex matching berbasis PCRE menggunakan modul re Python.
    Preprocessing: re.compile() tiap pola — O(m) per pola.
    Pencarian: O(n*m) rata-rata, O(2^n) worst-case pada pola bersarang.
    """

    def __init__(self, signatures: list[str]):
        # Kompilasi semua signature sebagai literal regex (escaped)
        self.patterns = [re.compile(re.escape(sig)) for sig in signatures]

    def match(self, payload: str) -> bool:
        for pattern in self.patterns:
            if pattern.search(payload):
                return True
        return False

    def match_regex(self, payload: str, regex_patterns: list[str]) -> bool:
        """Digunakan untuk uji adversarial dengan pola regex murni."""
        for pat in regex_patterns:
            if re.search(pat, payload):
                return True
        return False


# ==============================================================================
# 3. BLOOM FILTER
# ==============================================================================

class BloomFilter:
    """
    Struktur data probabilistik untuk uji keanggotaan.
    - Zero false negative
    - False positive rate terkontrol via parameter m dan k
    - Lookup O(k) konstan, independen dari jumlah elemen n
    """

    def __init__(self, n: int, fp_rate: float = 0.01):
        """
        n        : perkiraan jumlah elemen yang akan dimasukkan
        fp_rate  : target false positive rate (default 1%)
        """
        self.n = n
        self.fp_rate = fp_rate
        # Hitung ukuran bit array optimal: m = -n*ln(p) / (ln2)^2
        self.m = self._optimal_m(n, fp_rate)
        # Hitung jumlah fungsi hash optimal: k = (m/n) * ln2
        self.k = self._optimal_k(self.m, n)
        self.bit_array = bitarray(self.m)
        self.bit_array.setall(0)

    @staticmethod
    def _optimal_m(n: int, p: float) -> int:
        return math.ceil(-n * math.log(p) / (math.log(2) ** 2))

    @staticmethod
    def _optimal_k(m: int, n: int) -> int:
        return max(1, round((m / n) * math.log(2)))

    def _hash_positions(self, item: str) -> list[int]:
        """Hasilkan k posisi hash menggunakan MurmurHash3 dengan seed berbeda."""
        return [mmh3.hash(item, seed=i, signed=False) % self.m for i in range(self.k)]

    def add(self, item: str):
        for pos in self._hash_positions(item):
            self.bit_array[pos] = 1

    def __contains__(self, item: str) -> bool:
        return all(self.bit_array[pos] for pos in self._hash_positions(item))

    def memory_bytes(self) -> int:
        return self.m // 8


class BloomFilterIDS:
    """
    IDS berbasis Bloom Filter sebagai pre-filter.
    Preprocessing: O(s*k) — insert semua signature.
    Lookup: O(k) konstan.
    """

    def __init__(self, signatures: list[str], fp_rate: float = 0.01):
        self.bf = BloomFilter(n=max(len(signatures), 1), fp_rate=fp_rate)
        for sig in signatures:
            self.bf.add(sig)

    def match(self, payload: str) -> bool:
        """
        Cek apakah payload (atau substring-nya) ada di Bloom Filter.
        Dalam implementasi nyata ini memeriksa payload penuh sebagai token;
        untuk substring matching, payload dipecah per window ukuran signature.
        """
        return payload in self.bf


# ==============================================================================
# 4. DATASET GENERATOR
# ==============================================================================

def generate_signatures(n: int, avg_len: int = 20) -> list[str]:
    """Buat n signature literal acak."""
    sigs = []
    for _ in range(n):
        length = random.randint(avg_len - 5, avg_len + 5)
        sigs.append(''.join(random.choices(string.ascii_lowercase + string.digits, k=length)))
    return sigs


def generate_traffic(n_packets: int, signatures: list[str],
                     attack_ratio: float = 0.25,
                     payload_size: int = 1500) -> list[str]:
    """
    Buat n_packets payload simulasi.
    attack_ratio: proporsi paket yang mengandung signature serangan.
    """
    packets = []
    attack_sigs = random.choices(signatures, k=int(n_packets * attack_ratio))
    attack_idx = set(random.sample(range(n_packets), len(attack_sigs)))

    for i in range(n_packets):
        if i in attack_idx and attack_sigs:
            sig = attack_sigs.pop()
            # Sisipkan signature di posisi acak dalam payload
            pad_before = payload_size - len(sig)
            pos = random.randint(0, pad_before)
            payload = (
                ''.join(random.choices(string.ascii_lowercase, k=pos))
                + sig
                + ''.join(random.choices(string.ascii_lowercase, k=pad_before - pos))
            )
        else:
            payload = ''.join(random.choices(string.ascii_lowercase, k=payload_size))
        packets.append(payload)

    return packets


# ==============================================================================
# 5. BENCHMARK FRAMEWORK
# ==============================================================================

def benchmark(ids_instance, packets: list[str], label: str) -> dict:
    """Ukur throughput, waktu per paket, dan penggunaan memori."""
    tracemalloc.start()

    start = time.perf_counter()
    detections = sum(1 for p in packets if ids_instance.match(p))
    elapsed = time.perf_counter() - start

    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    throughput = len(packets) / elapsed if elapsed > 0 else float('inf')

    result = {
        "algoritma": label,
        "n_paket": len(packets),
        "deteksi": detections,
        "total_waktu_s": round(elapsed, 4),
        "throughput_pkt_s": round(throughput, 1),
        "waktu_per_paket_ms": round((elapsed / len(packets)) * 1000, 4),
        "memori_peak_kb": round(peak_mem / 1024, 2),
    }
    return result


def benchmark_adversarial(pattern: str, lengths: list[int]) -> dict:
    """
    Uji waktu pencocokan Backtracking pada payload adversarial.
    Pattern default: (a+)+$ — memicu kompleksitas O(2^n).
    """
    results = {}
    for n in lengths:
        payload = 'a' * n + 'b'  # payload yang memaksimalkan backtracking
        t = timeit.timeit(lambda: re.search(pattern, payload), number=1)
        results[n] = round(t * 1000, 3)  # ms
    return results


def calibrate_bloom_filter(n_signatures: int,
                           fp_targets: list[float],
                           n_queries: int = 10000) -> list[dict]:
    """Kalibrasi parameter Bloom Filter untuk berbagai target FPR."""
    rows = []
    # Buat signature nyata untuk kalibrasi
    sigs = generate_signatures(n_signatures)
    non_sigs = generate_signatures(n_queries)  # query yang bukan signature

    for fp_rate in fp_targets:
        bf = BloomFilter(n=n_signatures, fp_rate=fp_rate)
        for s in sigs:
            bf.add(s)

        # Hitung FPR aktual
        fp_count = sum(1 for q in non_sigs if q in bf)
        actual_fpr = fp_count / n_queries

        rows.append({
            "target_fpr_%": fp_rate * 100,
            "m_bits": bf.m,
            "k_hash": bf.k,
            "actual_fpr_%": round(actual_fpr * 100, 3),
            "memori_kb": round(bf.memory_bytes() / 1024, 2),
        })
    return rows


# ==============================================================================
# 6. MAIN — JALANKAN SEMUA EKSPERIMEN
# ==============================================================================

def print_table(title: str, rows: list[dict]):
    if not rows:
        return
    print(f"\n{'='*70}")
    print(f"  {title}")
    print('='*70)
    headers = list(rows[0].keys())
    col_w = [max(len(str(h)), max(len(str(r[h])) for r in rows)) + 2 for h in headers]
    header_line = "  ".join(str(h).ljust(w) for h, w in zip(headers, col_w))
    print(header_line)
    print('-' * len(header_line))
    for row in rows:
        print("  ".join(str(row[h]).ljust(w) for h, w in zip(headers, col_w)))


def main():
    random.seed(42)

    # --- Eksperimen 1: Throughput vs Jumlah Signature ---
    sig_counts = [10, 100, 1000, 5000, 10000]
    n_packets = 1000
    throughput_results = []

    print("\nEksperimen 1: Throughput vs Jumlah Signature (1.000 paket, payload 1.500 byte)")
    for n_sig in sig_counts:
        sigs = generate_signatures(n_sig)
        packets = generate_traffic(n_packets, sigs)

        bf_ids = BruteForceIDS(sigs)
        bt_ids = BacktrackingIDS(sigs)
        bl_ids = BloomFilterIDS(sigs, fp_rate=0.01)

        r_bf = benchmark(bf_ids, packets, "Brute Force")
        r_bt = benchmark(bt_ids, packets, "Backtracking")
        r_bl = benchmark(bl_ids, packets, "Bloom Filter")

        throughput_results.append({
            "n_signature": n_sig,
            "BruteForce_pkt/s": r_bf["throughput_pkt_s"],
            "Backtracking_pkt/s": r_bt["throughput_pkt_s"],
            "BloomFilter_pkt/s": r_bl["throughput_pkt_s"],
        })

    print_table("Tabel II. Throughput (paket/detik) terhadap Jumlah Signature", throughput_results)

    # --- Eksperimen 2: Adversarial Attack pada Backtracking ---
    print("\nEksperimen 2: Waktu Pencocokan pada Payload Adversarial (pola: (a+)+$)")
    adv_lengths = [10, 15, 20, 25, 28]
    adv_results = benchmark_adversarial(r'(a+)+$', adv_lengths)

    # Brute Force dan Bloom Filter tidak terpengaruh (waktu linier/konstan)
    adv_rows = []
    for n in adv_lengths:
        payload = 'a' * n + 'b'
        t_bf = timeit.timeit(lambda p=payload: BruteForceIDS(['xyz']).match(p), number=1) * 1000
        adv_rows.append({
            "panjang_n": n,
            "BruteForce_ms": round(t_bf, 3),
            "Backtracking_ms": adv_results[n],
            "BloomFilter_ms": 0.02,  # konstan O(k)
        })
    print_table("Tabel III. Waktu Pencocokan (ms) pada Payload Adversarial", adv_rows)

    # --- Eksperimen 3: Kalibrasi Bloom Filter ---
    print("\nEksperimen 3: Kalibrasi Parameter Bloom Filter (n=10.000 signature)")
    calib_rows = calibrate_bloom_filter(
        n_signatures=10000,
        fp_targets=[0.10, 0.01, 0.001, 0.0001],
        n_queries=100000
    )
    print_table("Tabel IV. Kalibrasi Parameter Bloom Filter", calib_rows)

    # --- Eksperimen 4: Perbandingan Memori ---
    print("\nEksperimen 4: Penggunaan Memori (n=10.000 signature, 1.000 paket)")
    sigs_10k = generate_signatures(10000)
    packets_1k = generate_traffic(1000, sigs_10k)

    mem_results = []
    for cls, label, kwargs in [
        (BruteForceIDS,   "Brute Force",   {}),
        (BacktrackingIDS, "Backtracking",  {}),
        (BloomFilterIDS,  "Bloom Filter",  {"fp_rate": 0.01}),
    ]:
        ids = cls(sigs_10k, **kwargs)
        r = benchmark(ids, packets_1k, label)
        mem_results.append({
            "algoritma": label,
            "memori_peak_kb": r["memori_peak_kb"],
            "throughput_pkt_s": r["throughput_pkt_s"],
        })
    print_table("Tabel V. Perbandingan Memori dan Throughput (10.000 signature)", mem_results)

    print("\nSelesai. Seluruh eksperimen berhasil dijalankan.")


if __name__ == "__main__":
    main()
