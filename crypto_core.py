import time
import secrets
# Library untuk AES-GCM dan ChaCha20 (pastikan sudah 'pip install pycryptodome')
from Crypto.Cipher import AES, ChaCha20
# Library untuk Ascon (pastikan sudah 'pip install ascon')
import ascon

def generate_random_bytes(size_in_bytes):
    """Fungsi untuk menghasilkan plaintext acak sesuai ukuran (bytes)"""
    return secrets.token_bytes(size_in_bytes)

def benchmark_cryptography():
    # 1. Parameter Pengujian Sesuai Ketentuan Dokumen
    message_sizes = [50, 100, 150, 200, 250] # Ukuran pesan dalam bytes
    num_samples = 100 # Minimal 100 sampel pengujian
    
    # Associated Data (AD) bebas, wajib dicantumkan di laporan PPT
    associated_data = b"Kelompok15_Case3_DataProteksiMQTT"
    
    # 3 Ukuran Kunci Berbeda (16 bytes, 24 bytes, 32 bytes)
    # Panjang karakter string disesuaikan agar persis mewakili byte yang diminta AES
    keys_dict = {
        16: b"KunciRahasia128B",                 # Tepat 16 karakter (128-bit)
        24: b"KunciRahasia192BitPanjan",         # Tepat 24 karakter (192-bit)
        32: b"KunciRahasia256BitPalingPanjang0"  # Tepat 32 karakter (256-bit)
    }

    print("==================================================================")
    print("Memulai Pengujian Computational Delay (Enkripsi + Dekripsi)")
    print("==================================================================")
    print("Algoritma | Ukuran Kunci (Bits) | Ukuran Pesan (Bytes) | Rata-rata Delay (Detik)")
    print("------------------------------------------------------------------")

    # Storage untuk hasil akhir (bisa dicopy ke Excel untuk bikin grafik)
    results = []

    # 2. Perulangan untuk mengevaluasi setiap skema
    for algo in ["AES-GCM", "ChaCha20", "Ascon-ECB"]:
        for key_size, key_bytes in keys_dict.items():
            for msg_size in message_sizes:
                
                total_time = 0.0
                
                # Pengujian 100 Sampel untuk Akurasi Data
                for _ in range(num_samples):
                    plaintext = generate_random_bytes(msg_size)
                    
                    #--- MULAI PROSES ALGORITMA ---
                    if algo == "AES-GCM":
                        # Catat waktu awal sebelum enkripsi
                        start_time = time.perf_counter()
                        
                        # Enkripsi AES-GCM
                        cipher_enc = AES.new(key_bytes, AES.MODE_GCM)
                        cipher_enc.update(associated_data)
                        ciphertext, tag = cipher_enc.encrypt_and_digest(plaintext)
                        nonce = cipher_enc.nonce
                        
                        # Dekripsi AES-GCM
                        cipher_dec = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
                        cipher_dec.update(associated_data)
                        decrypted_text = cipher_dec.decrypt_and_verify(ciphertext, tag)
                        
                        # Catat waktu akhir setelah dekripsi
                        end_time = time.perf_counter()

                    elif algo == "ChaCha20":
                        start_time = time.perf_counter()
                        
                        # Enkripsi ChaCha20
                        # PyCryptodome meminta kunci ChaCha20 selalu 32 byte. 
                        # Jika kunci pengujian kita kurang dari 32 byte, kita lakukan padding '0'
                        padded_key = key_bytes.ljust(32, b'\x00')
                        cipher_enc = ChaCha20.new(key=padded_key)
                        ciphertext = cipher_enc.encrypt(plaintext)
                        nonce = cipher_enc.nonce
                        
                        # Dekripsi ChaCha20
                        cipher_dec = ChaCha20.new(key=padded_key, nonce=nonce)
                        decrypted_text = cipher_dec.decrypt(ciphertext)
                        
                        end_time = time.perf_counter()

                    elif algo == "Ascon-ECB":
                        start_time = time.perf_counter()
                        
                        # Parameter Ascon
                        # Ascon-128a mensyaratkan kunci dan nonce tepat 16 byte
                        ascon_key = key_bytes[:16].ljust(16, b'\x00')
                        ascon_nonce = b"StaticNonce12345" # Tepat 16 karakter
                        
                        # Enkripsi Ascon
                        ciphertext = ascon.encrypt(
                            ascon_key, 
                            ascon_nonce, 
                            associated_data, 
                            plaintext, 
                            variant="Ascon-128a"
                        )
                        
                        # Dekripsi Ascon
                        decrypted_text = ascon.decrypt(
                            ascon_key, 
                            ascon_nonce, 
                            associated_data, 
                            ciphertext, 
                            variant="Ascon-128a"
                        )
                        
                        end_time = time.perf_counter()
                    
                    # Akumulasi total waktu pengerjaan (Enkripsi + Dekripsi)
                    total_time += (end_time - start_time)
                
                # Hitung rata-rata dari 100 sampel
                avg_delay = total_time / num_samples
                key_bits = key_size * 8
                
                # Tampilkan hasil langsung ke layar terminal
                print(f"{algo:<10} | {key_bits:<18} | {msg_size:<20} | {avg_delay:.8f}")
                results.append((algo, key_bits, msg_size, avg_delay))

    # 3. Ekspor ke file teks/CSV sederhana untuk bahan grafik
    with open("hasil_computational_delay.csv", "w") as f:
        f.write("Algoritma,Ukuran_Kunci_Bits,Ukuran_Pesan_Bytes,Rata_Rata_Delay_Detik\n")
        for res in results:
            f.write(f"{res[0]},{res[1]},{res[2]},{res[3]:.8f}\n")
    
    print("\n[SUKSES] Pengujian selesai! Data telah disimpan di 'hasil_computational_delay.csv'")

if __name__ == "__main__":
    benchmark_cryptography()