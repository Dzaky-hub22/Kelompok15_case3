import time
import secrets
from Crypto.Cipher import AES, ChaCha20
import ascon

def generate_random_bytes(size_in_bytes):
    return secrets.token_bytes(size_in_bytes)

# --- Ascon ECB Mode (enkripsi per-blok independen) ---
ASCON_BLOCK_SIZE = 16

def pkcs7_pad(data, block_size):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def ascon_ecb_encrypt(key, plaintext):
    padded = pkcs7_pad(plaintext, ASCON_BLOCK_SIZE)
    ciphertext = b""
    fixed_nonce = b'\x00' * 16
    for i in range(0, len(padded), ASCON_BLOCK_SIZE):
        block = padded[i:i+ASCON_BLOCK_SIZE]
        enc_block = ascon.encrypt(key, fixed_nonce, b"", block, "Ascon-128a")
        ciphertext += enc_block
    return ciphertext

def ascon_ecb_decrypt(key, ciphertext):
    chunk_size = ASCON_BLOCK_SIZE + 16
    plaintext = b""
    fixed_nonce = b'\x00' * 16
    for i in range(0, len(ciphertext), chunk_size):
        enc_block = ciphertext[i:i+chunk_size]
        dec_block = ascon.decrypt(key, fixed_nonce, b"", enc_block, "Ascon-128a")
        if dec_block is not None:
            plaintext += dec_block
    return pkcs7_unpad(plaintext)

def benchmark_cryptography():
    message_sizes = [50, 100, 150, 200, 250]
    num_samples = 100
    associated_data = b"Kelompok15_Case3_DataProteksiMQTT"

    keys_dict = {
        16: b"KunciRahasia128B",                 # 128-bit
        24: b"KunciRahasia192BitPanjan",         # 192-bit
        32: b"KunciRahasia256BitPalingPanjang0"  # 256-bit
    }

    print("==================================================================")
    print("Pengujian Computational Delay (Enkripsi + Dekripsi)")
    print("==================================================================")
    print("Algoritma | Kunci (Bits) | Pesan (Bytes) | Avg Delay (Detik)")
    print("------------------------------------------------------------------")

    results = []

    for algo in ["AES-GCM", "ChaCha20", "Ascon-ECB"]:
        for key_size, key_bytes in keys_dict.items():
            for msg_size in message_sizes:

                total_time = 0.0

                for _ in range(num_samples):
                    plaintext = generate_random_bytes(msg_size)

                    if algo == "AES-GCM":
                        start_time = time.perf_counter()
                        cipher_enc = AES.new(key_bytes, AES.MODE_GCM)
                        cipher_enc.update(associated_data)
                        ciphertext, tag = cipher_enc.encrypt_and_digest(plaintext)
                        nonce = cipher_enc.nonce
                        cipher_dec = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
                        cipher_dec.update(associated_data)
                        decrypted_text = cipher_dec.decrypt_and_verify(ciphertext, tag)
                        end_time = time.perf_counter()

                    elif algo == "ChaCha20":
                        start_time = time.perf_counter()
                        padded_key = key_bytes.ljust(32, b'\x00')
                        cipher_enc = ChaCha20.new(key=padded_key)
                        ciphertext = cipher_enc.encrypt(plaintext)
                        nonce = cipher_enc.nonce
                        cipher_dec = ChaCha20.new(key=padded_key, nonce=nonce)
                        decrypted_text = cipher_dec.decrypt(ciphertext)
                        end_time = time.perf_counter()

                    elif algo == "Ascon-ECB":
                        start_time = time.perf_counter()
                        ascon_key = key_bytes[:16].ljust(16, b'\x00')
                        ciphertext = ascon_ecb_encrypt(ascon_key, plaintext)
                        decrypted_text = ascon_ecb_decrypt(ascon_key, ciphertext)
                        end_time = time.perf_counter()

                    total_time += (end_time - start_time)

                avg_delay = total_time / num_samples
                key_bits = key_size * 8

                print(f"{algo:<10} | {key_bits:<12} | {msg_size:<13} | {avg_delay:.8f}")
                results.append((algo, key_bits, msg_size, avg_delay))

    with open("hasil_computational_delay.csv", "w") as f:
        f.write("Algoritma,Ukuran_Kunci_Bits,Ukuran_Pesan_Bytes,Rata_Rata_Delay_Detik\n")
        for res in results:
            f.write(f"{res[0]},{res[1]},{res[2]},{res[3]:.8f}\n")

    print("\n[SUKSES] Data disimpan di 'hasil_computational_delay.csv'")

if __name__ == "__main__":
    benchmark_cryptography()