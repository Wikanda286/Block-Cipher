"""
Metode 4: OFB (Output Feedback)
===============================
Rumus (Blok 1 Byte / 8 Bit):
- O_0       = IV
- Keystream : O_i = E_K(O_{i-1})
- Enkripsi  : C_i = P_i ⊕ O_i
- Dekripsi  : P_i = C_i ⊕ O_i   (identik dengan enkripsi, tetap memakai E_K)

Jalankan langsung:
    python ofb.py
    python ofb.py -p "HALO" -k "11" -v "45"
    python ofb.py -i
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


def ofb_generate_keystream(length: int, key: int, iv: int) -> list[int]:
    """Bangkitkan keystream O_1..O_n secara independen dari plaintext."""
    keystream: list[int] = []
    prev_o = iv
    for _ in range(length):
        o_i = encrypt_block(prev_o, key)
        keystream.append(o_i)
        prev_o = o_i
    return keystream


def ofb_encrypt(plaintext_blocks: list[int], key: int, iv: int, verbose: bool = True) -> list[int]:
    """Enkripsi OFB: O_i = E_K(O_{i-1}), C_i = P_i XOR O_i."""
    keystream = ofb_generate_keystream(len(plaintext_blocks), key, iv)
    ciphertext_blocks: list[int] = []
    if verbose:
        print("\n[OFB - ENKRIPSI] Rumus: O_i = E_K(O_{i-1}), C_i = P_i ⊕ O_i, O_0 = IV")
        print("-" * 68)
    prev_val = iv
    for i, (p_i, o_i) in enumerate(zip(plaintext_blocks, keystream), start=1):
        prev_label = "IV" if i == 1 else f"O{i - 1}"
        c_i = p_i ^ o_i
        ciphertext_blocks.append(c_i)
        if verbose:
            print(
                f"Blok {i}: O{i}=E_K({prev_label}={to_hex(prev_val)})={to_hex(o_i)} ({to_bin(o_i)}) "
                f"⊕ P{i}={to_hex(p_i)} "
                f"→ C{i}={to_hex(c_i)} ({to_bin(c_i)})"
            )
        prev_val = o_i
    if verbose:
        print(f"Hasil Ciphertext OFB (Hex) : {blocks_to_hex(ciphertext_blocks)}")
    return ciphertext_blocks


def ofb_decrypt(ciphertext_blocks: list[int], key: int, iv: int, verbose: bool = True) -> list[int]:
    """Dekripsi OFB: O_i = E_K(O_{i-1}), P_i = C_i XOR O_i (identik dengan enkripsi)."""
    keystream = ofb_generate_keystream(len(ciphertext_blocks), key, iv)
    plaintext_blocks: list[int] = []
    if verbose:
        print("\n[OFB - DEKRIPSI] Rumus: O_i = E_K(O_{i-1}), P_i = C_i ⊕ O_i (pakai E_K)")
        print("-" * 68)
    prev_val = iv
    for i, (c_i, o_i) in enumerate(zip(ciphertext_blocks, keystream), start=1):
        prev_label = "IV" if i == 1 else f"O{i - 1}"
        p_i = c_i ^ o_i
        plaintext_blocks.append(p_i)
        if verbose:
            print(
                f"Blok {i}: O{i}=E_K({prev_label}={to_hex(prev_val)})={to_hex(o_i)} ({to_bin(o_i)}) "
                f"⊕ C{i}={to_hex(c_i)} "
                f"→ P{i}={to_hex(p_i)} ({to_bin(p_i)}) {safe_char(p_i)}"
            )
        prev_val = o_i
    if verbose:
        recovered = blocks_to_text(plaintext_blocks)
        print(f"Hasil Dekripsi OFB         : {recovered!r} ({blocks_to_hex(plaintext_blocks)})")
    return plaintext_blocks


def run_ofb(plaintext: str, key: int, iv: int, show_input: bool = True) -> tuple[list[int], str]:
    """Jalankan enkripsi dan dekripsi OFB lengkap."""
    if show_input:
        print_input_summary(plaintext, key, iv, use_iv=True)
    p_blocks = text_to_blocks(plaintext)
    c_blocks = ofb_encrypt(p_blocks, key, iv, verbose=True)
    d_blocks = ofb_decrypt(c_blocks, key, iv, verbose=True)
    recovered = blocks_to_text(d_blocks)
    status = "OK (sesuai plaintext asli)" if recovered == plaintext else "GAGAL"
    print(f"Verifikasi OFB             : {status}")
    return c_blocks, recovered


if __name__ == "__main__":
    pt, k, iv_val = get_runtime_inputs("Simulasi Block Cipher - Mode OFB", use_iv=True)
    run_ofb(pt, k, iv_val, show_input=True)

