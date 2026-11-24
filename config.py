"""
Konfigurasi Bersama (1 Input untuk Semua Metode Block Cipher)
=============================================================
Ubah nilai PLAINTEXT, KEY_HEX, dan IV_HEX di file ini,
maka ecb.py, cbc.py, cfb.py, ofb.py, dan main.py otomatis mengikuti.

Catatan sesuai materi (BlockCipher.pdf & Praktik_Block_Cipher.xlsx):
- Ukuran blok   : 8 bit = 1 byte (1 karakter ASCII = 1 blok)
- Fungsi E_K(X) : X XOR K
- Fungsi D_K(X) : X XOR K
"""

import argparse
import sys

# =====================================================================
# PENGATURAN INPUT UTAMA (UBAH DI SINI — BERLAKU UNTUK SEMUA FILE)
# =====================================================================
PLAINTEXT = "APA"   # Teks ASCII bebas (panjang dinamis, tidak harus 3 huruf)
KEY_HEX = "11"      # Kunci 1 byte dalam heksadesimal (00 - FF)
IV_HEX = "45"       # Initialization Vector 1 byte dalam heksadesimal (00 - FF)


# Pastikan simbol Unicode (⊕, →) aman tampil di terminal Windows
def setup_console_encoding() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


# =====================================================================
# FUNGSI BANTU KONVERSI & BLOK CIPHER DASAR (1 BYTE / 8 BIT)
# =====================================================================
def parse_hex_byte(hex_str: str, nama: str = "Nilai") -> int:
    """Konversi string heksadesimal (mis. '11', '0x45', 'A5') ke integer 0..255."""
    cleaned = hex_str.strip().lower().removeprefix("0x")
    if not cleaned:
        raise ValueError(f"{nama} tidak boleh kosong.")
    try:
        value = int(cleaned, 16)
    except ValueError as exc:
        raise ValueError(f"{nama} '{hex_str}' bukan format heksadesimal yang valid.") from exc
    if not (0 <= value <= 0xFF):
        raise ValueError(f"{nama} harus berukuran 1 byte (00 sampai FF), bukan '{hex_str}'.")
    return value


def text_to_blocks(plaintext: str) -> list[int]:
    """Pecah string plaintext menjadi daftar blok 1 byte (nilai ASCII 0..255)."""
    if not plaintext:
        raise ValueError("Plaintext tidak boleh kosong.")
    blocks: list[int] = []
    for ch in plaintext:
        code = ord(ch)
        if code > 0xFF:
            raise ValueError(
                f"Karakter '{ch}' (U+{code:04X}) melebihi 1 byte (ASCII/Latin-1)."
            )
        blocks.append(code)
    return blocks


def blocks_to_text(blocks: list[int]) -> str:
    """Gabungkan daftar blok 1 byte kembali menjadi teks."""
    return "".join(chr(b) for b in blocks)


def to_bin(byte_val: int) -> str:
    """Format 1 byte menjadi string biner 8 bit (contoh: '01000001')."""
    return f"{byte_val & 0xFF:08b}"


def to_hex(byte_val: int) -> str:
    """Format 1 byte menjadi string heksadesimal 2 digit kapital (contoh: '41')."""
    return f"{byte_val & 0xFF:02X}"


def blocks_to_hex(blocks: list[int]) -> str:
    """Format daftar blok menjadi rangkaian hex dipisah spasi (contoh: '50 41 50')."""
    return " ".join(to_hex(b) for b in blocks)


def safe_char(byte_val: int) -> str:
    """Tampilkan karakter ASCII jika printable, selain itu tampilkan representasi aman."""
    if 32 <= byte_val <= 126:
        return f"'{chr(byte_val)}'"
    return f"(non-printable 0x{to_hex(byte_val)})"


def encrypt_block(block: int, key: int) -> int:
    """Fungsi enkripsi blok dasar E_K(X) = X XOR K (sesuai Praktik_Block_Cipher.xlsx)."""
    return (block ^ key) & 0xFF


def decrypt_block(block: int, key: int) -> int:
    """Fungsi dekripsi blok dasar D_K(X) = X XOR K (sesuai Praktik_Block_Cipher.xlsx)."""
    return (block ^ key) & 0xFF


def print_input_summary(plaintext: str, key: int, iv: int, use_iv: bool = True) -> None:
    """Tampilkan ringkasan input & pemecahan blok plaintext (seperti sheet Input di Excel)."""
    blocks = text_to_blocks(plaintext)
    print("=" * 68)
    print("INPUT & PEMECAHAN BLOK (1 BLOK = 8 BIT = 1 BYTE)")
    print("=" * 68)
    print(f"Plaintext : {plaintext!r} ({len(blocks)} blok)")
    print(f"Key (K)   : {to_hex(key)} (hex) = {to_bin(key)} (biner)")
    if use_iv:
        print(f"IV        : {to_hex(iv)} (hex) = {to_bin(iv)} (biner)")
    else:
        print("IV        : (ECB tidak menggunakan IV)")
    print("-" * 68)
    print(f"{'Blok':<6} | {'Karakter':<10} | {'ASCII (Hex)':<12} | {'Biner (8 bit)':<14}")
    print("-" * 68)
    for i, b in enumerate(blocks, start=1):
        print(f"P{i:<5} | {safe_char(b):<10} | {to_hex(b):<12} | {to_bin(b):<14}")
    print("=" * 68)


def get_runtime_inputs(
    description: str,
    use_iv: bool = True,
) -> tuple[str, int, int]:
    """
    Ambil input dari config.py secara default.
    Mendukung override dinamis lewat argumen CLI (-p, -k, -v) atau mode interaktif (-i).
    """
    setup_console_encoding()
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "-p", "--plaintext",
        default=None,
        help=f"Plaintext kustom (default dari config.py: {PLAINTEXT!r})",
    )
    parser.add_argument(
        "-k", "--key",
        default=None,
        help=f"Key 1 byte dalam hex (default dari config.py: {KEY_HEX})",
    )
    if use_iv:
        parser.add_argument(
            "-v", "--iv",
            default=None,
            help=f"IV 1 byte dalam hex (default dari config.py: {IV_HEX})",
        )
    parser.add_argument(
        "-i", "--interaktif",
        action="store_true",
        help="Masukkan Plaintext, Key, dan IV secara interaktif lewat terminal",
    )
    args = parser.parse_args()

    pt_str = args.plaintext if args.plaintext is not None else PLAINTEXT
    key_str = args.key if args.key is not None else KEY_HEX
    iv_str = (getattr(args, "iv", None) if use_iv else None) or IV_HEX

    if args.interaktif:
        print("Mode Input Interaktif (tekan Enter untuk memakai nilai default dari config.py)")
        in_pt = input(f"  Plaintext [{pt_str}]: ")
        if in_pt != "":
            pt_str = in_pt
        in_key = input(f"  Key (hex 1 byte) [{key_str}]: ").strip()
        if in_key != "":
            key_str = in_key
        if use_iv:
            in_iv = input(f"  IV (hex 1 byte) [{iv_str}]: ").strip()
            if in_iv != "":
                iv_str = in_iv
        print()

    # Validasi input
    text_to_blocks(pt_str)
    key_val = parse_hex_byte(key_str, "Key")
    iv_val = parse_hex_byte(iv_str, "IV")
    return pt_str, key_val, iv_val

