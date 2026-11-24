"""
Metode 1: ECB (Electronic Code Book)
====================================
Rumus (Blok 1 Byte / 8 Bit):
- Enkripsi : C_i = E_K(P_i)
- Dekripsi : P_i = D_K(C_i)
- Catatan  : ECB tidak menggunakan IV.

Jalankan langsung:
    python ecb.py
    python ecb.py -p "HALO" -k "11"
    python ecb.py -i
"""

from config import (
    blocks_to_hex,
    blocks_to_text,
    decrypt_block,
    encrypt_block,
    get_runtime_inputs,
    print_input_summary,
    safe_char,
    text_to_blocks,
    to_bin,
    to_hex,
)


def ecb_encrypt(plaintext_blocks: list[int], key: int, verbose: bool = True) -> list[int]:
    """Enkripsi ECB: C_i = E_K(P_i)."""
    ciphertext_blocks: list[int] = []
    if verbose:
        print("\n[ECB - ENKRIPSI] Rumus: C_i = E_K(P_i)")
        print("-" * 68)
    for i, p_i in enumerate(plaintext_blocks, start=1):
        c_i = encrypt_block(p_i, key)
        ciphertext_blocks.append(c_i)
        if verbose:
            print(
                f"Blok {i}: P{i}={to_hex(p_i)} ({to_bin(p_i)}) "
                f"⊕ K={to_hex(key)} ({to_bin(key)}) "
                f"→ C{i}={to_hex(c_i)} ({to_bin(c_i)})"
            )
    if verbose:
        print(f"Hasil Ciphertext ECB (Hex) : {blocks_to_hex(ciphertext_blocks)}")
    return ciphertext_blocks


def ecb_decrypt(ciphertext_blocks: list[int], key: int, verbose: bool = True) -> list[int]:
    """Dekripsi ECB: P_i = D_K(C_i)."""
    plaintext_blocks: list[int] = []
    if verbose:
        print("\n[ECB - DEKRIPSI] Rumus: P_i = D_K(C_i)")
        print("-" * 68)
    for i, c_i in enumerate(ciphertext_blocks, start=1):
        p_i = decrypt_block(c_i, key)
        plaintext_blocks.append(p_i)
        if verbose:
            print(
                f"Blok {i}: C{i}={to_hex(c_i)} ({to_bin(c_i)}) "
                f"⊕ K={to_hex(key)} ({to_bin(key)}) "
                f"→ P{i}={to_hex(p_i)} ({to_bin(p_i)}) {safe_char(p_i)}"
            )
    if verbose:
        recovered = blocks_to_text(plaintext_blocks)
        print(f"Hasil Dekripsi ECB         : {recovered!r} ({blocks_to_hex(plaintext_blocks)})")
    return plaintext_blocks


def run_ecb(plaintext: str, key: int, show_input: bool = True) -> tuple[list[int], str]:
    """Jalankan enkripsi dan dekripsi ECB lengkap."""
    if show_input:
        print_input_summary(plaintext, key, 0, use_iv=False)
    p_blocks = text_to_blocks(plaintext)
    c_blocks = ecb_encrypt(p_blocks, key, verbose=True)
    d_blocks = ecb_decrypt(c_blocks, key, verbose=True)
    recovered = blocks_to_text(d_blocks)
    status = "OK (sesuai plaintext asli)" if recovered == plaintext else "GAGAL"
    print(f"Verifikasi ECB             : {status}")
    return c_blocks, recovered


if __name__ == "__main__":
    pt, k, _ = get_runtime_inputs("Simulasi Block Cipher - Mode ECB", use_iv=False)
    run_ecb(pt, k, show_input=True)

