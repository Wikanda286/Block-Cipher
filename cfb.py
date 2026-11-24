"""
Metode 3: CFB (Cipher Feedback)
===============================
Rumus (Blok 1 Byte / 8 Bit):
- C_0      = IV
- Enkripsi : C_i = P_i ⊕ E_K(C_{i-1})
- Dekripsi : P_i = C_i ⊕ E_K(C_{i-1})   (tetap memakai E_K, bukan D_K)

Jalankan langsung:
    python cfb.py
    python cfb.py -p "HALO" -k "11" -v "45"
    python cfb.py -i
"""

from config import (
    blocks_to_hex,
    blocks_to_text,
    encrypt_block,
    get_runtime_inputs,
    print_input_summary,
    safe_char,
    text_to_blocks,
    to_bin,
    to_hex,
)


def cfb_encrypt(plaintext_blocks: list[int], key: int, iv: int, verbose: bool = True) -> list[int]:
    """Enkripsi CFB: C_i = P_i XOR E_K(C_{i-1}), dengan C_0 = IV."""
    ciphertext_blocks: list[int] = []
    prev_c = iv
    if verbose:
        print("\n[CFB - ENKRIPSI] Rumus: C_i = P_i ⊕ E_K(C_{i-1}), C_0 = IV")
        print("-" * 68)
    for i, p_i in enumerate(plaintext_blocks, start=1):
        prev_label = "IV" if i == 1 else f"C{i - 1}"
        ek_prev = encrypt_block(prev_c, key)
        c_i = p_i ^ ek_prev
        ciphertext_blocks.append(c_i)
        if verbose:
            print(
                f"Blok {i}: E_K({prev_label}={to_hex(prev_c)})={to_hex(ek_prev)} ({to_bin(ek_prev)}) "
                f"⊕ P{i}={to_hex(p_i)} "
                f"→ C{i}={to_hex(c_i)} ({to_bin(c_i)})"
            )
        prev_c = c_i
    if verbose:
        print(f"Hasil Ciphertext CFB (Hex) : {blocks_to_hex(ciphertext_blocks)}")
    return ciphertext_blocks


def cfb_decrypt(ciphertext_blocks: list[int], key: int, iv: int, verbose: bool = True) -> list[int]:
    """Dekripsi CFB: P_i = C_i XOR E_K(C_{i-1}), tetap memakai E_K."""
    plaintext_blocks: list[int] = []
    prev_c = iv
    if verbose:
        print("\n[CFB - DEKRIPSI] Rumus: P_i = C_i ⊕ E_K(C_{i-1}), C_0 = IV (pakai E_K)")
        print("-" * 68)
    for i, c_i in enumerate(ciphertext_blocks, start=1):
        prev_label = "IV" if i == 1 else f"C{i - 1}"
        ek_prev = encrypt_block(prev_c, key)
        p_i = c_i ^ ek_prev
        plaintext_blocks.append(p_i)
        if verbose:
            print(
                f"Blok {i}: E_K({prev_label}={to_hex(prev_c)})={to_hex(ek_prev)} ({to_bin(ek_prev)}) "
                f"⊕ C{i}={to_hex(c_i)} "
                f"→ P{i}={to_hex(p_i)} ({to_bin(p_i)}) {safe_char(p_i)}"
            )
        prev_c = c_i
    if verbose:
        recovered = blocks_to_text(plaintext_blocks)
        print(f"Hasil Dekripsi CFB         : {recovered!r} ({blocks_to_hex(plaintext_blocks)})")
    return plaintext_blocks


def run_cfb(plaintext: str, key: int, iv: int, show_input: bool = True) -> tuple[list[int], str]:
    """Jalankan enkripsi dan dekripsi CFB lengkap."""
    if show_input:
        print_input_summary(plaintext, key, iv, use_iv=True)
    p_blocks = text_to_blocks(plaintext)
    c_blocks = cfb_encrypt(p_blocks, key, iv, verbose=True)
    d_blocks = cfb_decrypt(c_blocks, key, iv, verbose=True)
    recovered = blocks_to_text(d_blocks)
    status = "OK (sesuai plaintext asli)" if recovered == plaintext else "GAGAL"
    print(f"Verifikasi CFB             : {status}")
    return c_blocks, recovered


if __name__ == "__main__":
    pt, k, iv_val = get_runtime_inputs("Simulasi Block Cipher - Mode CFB", use_iv=True)
    run_cfb(pt, k, iv_val, show_input=True)

