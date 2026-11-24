"""
Metode 2: CBC (Cipher Block Chaining)
=====================================
Rumus (Blok 1 Byte / 8 Bit):
- C_0      = IV
- Enkripsi : C_i = E_K(P_i ⊕ C_{i-1})
- Dekripsi : P_i = D_K(C_i) ⊕ C_{i-1}

Jalankan langsung:
    python cbc.py
    python cbc.py -p "HALO" -k "11" -v "45"
    python cbc.py -i
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


def cbc_encrypt(plaintext_blocks: list[int], key: int, iv: int, verbose: bool = True) -> list[int]:
    """Enkripsi CBC: C_i = E_K(P_i XOR C_{i-1}), dengan C_0 = IV."""
    ciphertext_blocks: list[int] = []
    prev_c = iv
    if verbose:
        print("\n[CBC - ENKRIPSI] Rumus: C_i = E_K(P_i ⊕ C_{i-1}), C_0 = IV")
        print("-" * 68)
    for i, p_i in enumerate(plaintext_blocks, start=1):
        prev_label = "IV" if i == 1 else f"C{i - 1}"
        xored = p_i ^ prev_c
        c_i = encrypt_block(xored, key)
        ciphertext_blocks.append(c_i)
        if verbose:
            print(
                f"Blok {i}: P{i}={to_hex(p_i)} ⊕ {prev_label}={to_hex(prev_c)} "
                f"→ {to_hex(xored)} ({to_bin(xored)}) "
                f"→ E_K → C{i}={to_hex(c_i)} ({to_bin(c_i)})"
            )
        prev_c = c_i
    if verbose:
        print(f"Hasil Ciphertext CBC (Hex) : {blocks_to_hex(ciphertext_blocks)}")
    return ciphertext_blocks


def cbc_decrypt(ciphertext_blocks: list[int], key: int, iv: int, verbose: bool = True) -> list[int]:
    """Dekripsi CBC: P_i = D_K(C_i) XOR C_{i-1}, dengan C_0 = IV."""
    plaintext_blocks: list[int] = []
    prev_c = iv
    if verbose:
        print("\n[CBC - DEKRIPSI] Rumus: P_i = D_K(C_i) ⊕ C_{i-1}, C_0 = IV")
        print("-" * 68)
    for i, c_i in enumerate(ciphertext_blocks, start=1):
        prev_label = "IV" if i == 1 else f"C{i - 1}"
        decrypted = decrypt_block(c_i, key)
        p_i = decrypted ^ prev_c
        plaintext_blocks.append(p_i)
        if verbose:
            print(
                f"Blok {i}: D_K(C{i}={to_hex(c_i)})={to_hex(decrypted)} ({to_bin(decrypted)}) "
                f"⊕ {prev_label}={to_hex(prev_c)} "
                f"→ P{i}={to_hex(p_i)} ({to_bin(p_i)}) {safe_char(p_i)}"
            )
        prev_c = c_i
    if verbose:
        recovered = blocks_to_text(plaintext_blocks)
        print(f"Hasil Dekripsi CBC         : {recovered!r} ({blocks_to_hex(plaintext_blocks)})")
    return plaintext_blocks


def run_cbc(plaintext: str, key: int, iv: int, show_input: bool = True) -> tuple[list[int], str]:
    """Jalankan enkripsi dan dekripsi CBC lengkap."""
    if show_input:
        print_input_summary(plaintext, key, iv, use_iv=True)
    p_blocks = text_to_blocks(plaintext)
    c_blocks = cbc_encrypt(p_blocks, key, iv, verbose=True)
    d_blocks = cbc_decrypt(c_blocks, key, iv, verbose=True)
    recovered = blocks_to_text(d_blocks)
    status = "OK (sesuai plaintext asli)" if recovered == plaintext else "GAGAL"
    print(f"Verifikasi CBC             : {status}")
    return c_blocks, recovered


if __name__ == "__main__":
    pt, k, iv_val = get_runtime_inputs("Simulasi Block Cipher - Mode CBC", use_iv=True)
    run_cbc(pt, k, iv_val, show_input=True)

