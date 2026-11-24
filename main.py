"""
Program Utama: Simulasi 4 Metode Block Cipher (ECB, CBC, CFB, OFB)
==================================================================
Semua metode membaca 1 input yang sama dari config.py:
- PLAINTEXT = "APA"
- KEY_HEX   = "11"
- IV_HEX    = "45"

Cara menjalankan:
1. Default (membaca config.py):
       python main.py
2. Mode interaktif (ketik langsung di terminal):
       python main.py -i
3. Override cepat lewat argumen CLI:
       python main.py -p "KRIPTO" -k "A5" -v "3C"
"""

from cbc import run_cbc
from cfb import run_cfb
from config import blocks_to_hex, get_runtime_inputs, print_input_summary
from ecb import run_ecb
from ofb import run_ofb


def main() -> None:
    plaintext, key, iv = get_runtime_inputs(
        "Simulasi 4 Mode Block Cipher (ECB, CBC, CFB, OFB) - Blok 1 Byte",
        use_iv=True,
    )

    print_input_summary(plaintext, key, iv, use_iv=True)

    results: list[tuple[str, list[int], str]] = []

    print("\n" + "#" * 68)
    print("1. MODE ECB (Electronic Code Book)")
    print("#" * 68)
    c_ecb, d_ecb = run_ecb(plaintext, key, show_input=False)
    results.append(("ECB", c_ecb, d_ecb))

    print("\n" + "#" * 68)
    print("2. MODE CBC (Cipher Block Chaining)")
    print("#" * 68)
    c_cbc, d_cbc = run_cbc(plaintext, key, iv, show_input=False)
    results.append(("CBC", c_cbc, d_cbc))

    print("\n" + "#" * 68)
    print("3. MODE CFB (Cipher Feedback)")
    print("#" * 68)
    c_cfb, d_cfb = run_cfb(plaintext, key, iv, show_input=False)
    results.append(("CFB", c_cfb, d_cfb))

    print("\n" + "#" * 68)
    print("4. MODE OFB (Output Feedback)")
    print("#" * 68)
    c_ofb, d_ofb = run_ofb(plaintext, key, iv, show_input=False)
    results.append(("OFB", c_ofb, d_ofb))

    print("\n" + "=" * 68)
    print("RINGKASAN PERBANDINGAN 4 METODE BLOCK CIPHER")
    print("=" * 68)
    print(f"{'Mode':<6} | {'Ciphertext (Hex)':<32} | {'Dekripsi':<14} | Status")
    print("-" * 68)
    for mode, cipher_blocks, decrypted in results:
        status = "OK" if decrypted == plaintext else "GAGAL"
        print(f"{mode:<6} | {blocks_to_hex(cipher_blocks):<32} | {decrypted!r:<14} | {status}")
    print("=" * 68)


if __name__ == "__main__":
    main()

