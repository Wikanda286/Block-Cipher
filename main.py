"""
Program Utama: Simulasi 4 Metode Block Cipher (ECB, CBC, CFB, OFB)
==================================================================
Semua metode membaca 1 input yang sama dari config.py:
- PLAINTEXT = "APA"
- KEY_HEX   = "11"
- IV_HEX    = "45"

Alur program:
1. Pilih salah satu dari 4 metode (ECB, CBC, CFB, OFB) atau jalankan semua.
2. Setelah metode selesai dijalankan, pengguna dapat memilih ulang atau selesai.

Cara menjalankan:
1. Default (membaca config.py):
       python main.py
2. Mode interaktif input awal:
       python main.py -i
3. Override cepat lewat argumen CLI:
       python main.py -p "KRIPTO" -k "A5" -v "3C"
"""

from cbc import run_cbc
from cfb import run_cfb
from config import (
    blocks_to_hex,
    get_runtime_inputs,
    parse_hex_byte,
    print_input_summary,
    text_to_blocks,
    to_hex,
)
from ecb import run_ecb
from ofb import run_ofb


def run_all_modes(plaintext: str, key: int, iv: int) -> None:
    """Jalankan semua 4 metode sekaligus beserta tabel perbandingan."""
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


def prompt_update_inputs(plaintext: str, key: int, iv: int) -> tuple[str, int, int]:
    """Ubah Plaintext, Key, dan IV secara dinamis dari menu."""
    print("\nUbah Input (tekan Enter untuk mempertahankan nilai saat ini)")
    try:
        new_pt = input(f"  Plaintext [{plaintext}]: ")
        candidate_pt = new_pt if new_pt != "" else plaintext
        text_to_blocks(candidate_pt)

        new_key_str = input(f"  Key (hex 1 byte) [{to_hex(key)}]: ").strip()
        candidate_key = parse_hex_byte(new_key_str, "Key") if new_key_str else key

        new_iv_str = input(f"  IV (hex 1 byte) [{to_hex(iv)}]: ").strip()
        candidate_iv = parse_hex_byte(new_iv_str, "IV") if new_iv_str else iv

        print("Input berhasil diperbarui.")
        return candidate_pt, candidate_key, candidate_iv
    except ValueError as err:
        print(f"Input tidak valid: {err} (tetap memakai input sebelumnya)")
        return plaintext, key, iv


def ask_continue() -> bool:
    """Tanyakan apakah pengguna ingin memilih metode lagi atau selesai."""
    while True:
        jawab = input("\nIngin memilih metode lagi? (y = pilih ulang / n = selesai) [y]: ").strip().lower()
        if jawab in ("", "y", "ya", "yes"):
            return True
        if jawab in ("n", "no", "t", "tidak", "selesai"):
            return False
        print("Masukkan 'y' untuk memilih ulang atau 'n' untuk selesai.")


def print_menu(plaintext: str, key: int, iv: int) -> None:
    """Tampilkan menu pemilihan 4 metode block cipher."""
    print("\n" + "=" * 68)
    print("SIMULASI BLOCK CIPHER - PILIH METODE")
    print("=" * 68)
    print(f"Input aktif -> Plaintext: {plaintext!r} | Key: {to_hex(key)} | IV: {to_hex(iv)}")
    print("-" * 68)
    print("1. ECB (Electronic Code Book)")
    print("2. CBC (Cipher Block Chaining)")
    print("3. CFB (Cipher Feedback)")
    print("4. OFB (Output Feedback)")
    print("5. Jalankan Semua 4 Metode (ECB, CBC, CFB, OFB)")
    print("6. Ubah Plaintext / Key / IV")
    print("0. Selesai")
    print("=" * 68)


def main() -> None:
    plaintext, key, iv = get_runtime_inputs(
        "Simulasi 4 Mode Block Cipher (ECB, CBC, CFB, OFB) - Blok 1 Byte",
        use_iv=True,
    )

    try:
        while True:
            print_menu(plaintext, key, iv)
            pilihan = input("Pilih metode (0-6): ").strip()

            if pilihan == "1":
                print("\n" + "#" * 68)
                print("MODE ECB (Electronic Code Book)")
                print("#" * 68)
                run_ecb(plaintext, key, show_input=True)
            elif pilihan == "2":
                print("\n" + "#" * 68)
                print("MODE CBC (Cipher Block Chaining)")
                print("#" * 68)
                run_cbc(plaintext, key, iv, show_input=True)
            elif pilihan == "3":
                print("\n" + "#" * 68)
                print("MODE CFB (Cipher Feedback)")
                print("#" * 68)
                run_cfb(plaintext, key, iv, show_input=True)
            elif pilihan == "4":
                print("\n" + "#" * 68)
                print("MODE OFB (Output Feedback)")
                print("#" * 68)
                run_ofb(plaintext, key, iv, show_input=True)
            elif pilihan == "5":
                run_all_modes(plaintext, key, iv)
            elif pilihan == "6":
                plaintext, key, iv = prompt_update_inputs(plaintext, key, iv)
                continue
            elif pilihan == "0":
                print("\nProgram selesai. Terima kasih!")
                break
            else:
                print("\nPilihan tidak valid. Silakan pilih angka 0 sampai 6.")
                continue

            if not ask_continue():
                print("\nProgram selesai. Terima kasih!")
                break
    except (KeyboardInterrupt, EOFError):
        print("\nProgram selesai.")


if __name__ == "__main__":
    main()
