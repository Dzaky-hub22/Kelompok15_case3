import time
import secrets
import threading
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES, ChaCha20
import ascon

# --- PENGATURAN MQTT HIVEMQ ---
MQTT_BROKER = "broker.hivemq.com"
MQTT_PORT = 1883
# Gunakan topik unik agar tidak bertabrakan dengan orang lain
MQTT_TOPIC = "telkom/kelompok15/case3/transmission_test"

# Variabel Global untuk sinkronisasi thread pengukuran waktu
received_event = threading.Event()
receive_time = 0.0

# Callback ketika berhasil connect ke broker
def on_connect(client, userdata, flags, rc):
    client.subscribe(MQTT_TOPIC)

# Callback ketika pesan diterima
def on_message(client, userdata, msg):
    global receive_time
    # Langsung catat waktu sesaat setelah pesan masuk
    receive_time = time.perf_counter() 
    received_event.set() # Beri sinyal ke program utama bahwa pesan sudah sampai

def generate_random_bytes(size):
    return secrets.token_bytes(size)

def benchmark_transmission():
    # Setup MQTT Client
    client = mqtt.Client(client_id="Kelompok15_TestNode")
    client.on_connect = on_connect
    client.on_message = on_message
    
    print(f"Menghubungkan ke Broker: {MQTT_BROKER}...")
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    client.loop_start() # Jalankan thread MQTT di background
    
    # Tunggu sebentar agar koneksi stabil
    time.sleep(2)
    print("Terhubung! Memulai Pengujian Transmission Delay...\n")

    message_sizes = [50, 100, 150, 200, 250]
    num_samples = 100
    associated_data = b"Kelompok15_Case3_DataProteksiMQTT"
    keys_dict = {
        16: b"KunciRahasia128B",                 
        24: b"KunciRahasia192BitPanjan",         
        32: b"KunciRahasia256BitPalingPanjang0"  
    }

    print("Algoritma | Kunci(Bits) | Pesan(Bytes) | Rata-rata Transmission (Detik)")
    print("-" * 70)

    results = []

    for algo in ["AES-GCM", "ChaCha20", "Ascon-ECB"]:
        for key_size, key_bytes in keys_dict.items():
            for msg_size in message_sizes:
                
                total_delay = 0.0
                plaintext = generate_random_bytes(msg_size)
                
                # Kita pre-enkripsi pesannya untuk mendapatkan ukuran payload asli
                # yang akan dikirim via MQTT (termasuk tag dan nonce)
                if algo == "AES-GCM":
                    cipher_enc = AES.new(key_bytes, AES.MODE_GCM)
                    cipher_enc.update(associated_data)
                    ciphertext, tag = cipher_enc.encrypt_and_digest(plaintext)
                    payload = cipher_enc.nonce + tag + ciphertext
                
                elif algo == "ChaCha20":
                    padded_key = key_bytes.ljust(32, b'\x00')
                    cipher_enc = ChaCha20.new(key=padded_key)
                    ciphertext = cipher_enc.encrypt(plaintext)
                    payload = cipher_enc.nonce + ciphertext
                
                elif algo == "Ascon-ECB":
                    ascon_key = key_bytes[:16].ljust(16, b'\x00')
                    ascon_nonce = b"StaticNonce12345"
                    ciphertext = ascon.encrypt(ascon_key, ascon_nonce, associated_data, plaintext, "Ascon-128a")
                    payload = ascon_nonce + ciphertext

                # Lakukan pengiriman 100 kali
                for _ in range(num_samples):
                    received_event.clear()
                    
                    # Catat waktu awal
                    send_time = time.perf_counter()
                    
                    # Publish pesan
                    client.publish(MQTT_TOPIC, payload, qos=0)
                    
                    # Tunggu sampai pesan diterima (maksimal 5 detik agar tidak hang)
                    if received_event.wait(timeout=5.0):
                        delay = receive_time - send_time
                        total_delay += delay
                    else:
                        print(f"Peringatan: Timeout pada {algo} ukuran {msg_size}!")
                        # Tambahkan penalti waktu atau abaikan
                        total_delay += 5.0 
                        
                # Hitung rata-rata
                avg_delay = total_delay / num_samples
                key_bits = key_size * 8
                
                print(f"{algo:<10} | {key_bits:<11} | {msg_size:<12} | {avg_delay:.5f}")
                results.append((algo, key_bits, msg_size, avg_delay))

    # Matikan koneksi setelah selesai
    client.loop_stop()
    client.disconnect()

    # Ekspor ke CSV
    with open("hasil_transmission_delay.csv", "w") as f:
        f.write("Algoritma,Ukuran_Kunci_Bits,Ukuran_Pesan_Bytes,Rata_Rata_Transmission_Detik\n")
        for res in results:
            f.write(f"{res[0]},{res[1]},{res[2]},{res[3]:.5f}\n")
    
    print("\n[SUKSES] Pengujian Transmission selesai! Disimpan di 'hasil_transmission_delay.csv'")

if __name__ == "__main__":
    benchmark_transmission()