import time
import secrets
import threading
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES, ChaCha20
import ascon

# --- Pengaturan MQTT ---
MQTT_BROKER = "broker.hivemq.com"
MQTT_PORT = 1883
MQTT_TOPIC = "telkom/kelompok15/case3/transmission_test"

received_event = threading.Event()
receive_time = 0.0

def on_connect(client, userdata, flags, rc):
    client.subscribe(MQTT_TOPIC)

def on_message(client, userdata, msg):
    global receive_time
    receive_time = time.perf_counter()
    received_event.set()

def generate_random_bytes(size):
    return secrets.token_bytes(size)

# --- Ascon ECB Mode (enkripsi per-blok independen) ---
ASCON_BLOCK_SIZE = 16

def pkcs7_pad(data, block_size):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def ascon_ecb_encrypt(key, plaintext):
    padded = pkcs7_pad(plaintext, ASCON_BLOCK_SIZE)
    ciphertext = b""
    fixed_nonce = b'\x00' * 16
    for i in range(0, len(padded), ASCON_BLOCK_SIZE):
        block = padded[i:i+ASCON_BLOCK_SIZE]
        enc_block = ascon.encrypt(key, fixed_nonce, b"", block, "Ascon-128a")
        ciphertext += enc_block
    return ciphertext

def benchmark_transmission():
    client = mqtt.Client(client_id="Kelompok15_TestNode")
    client.on_connect = on_connect
    client.on_message = on_message

    print(f"Menghubungkan ke Broker: {MQTT_BROKER}...")
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    client.loop_start()

    time.sleep(2)
    print("Terhubung! Memulai Pengujian Transmission Delay...\n")

    message_sizes = [50, 100, 150, 200, 250]
    num_samples = 100
    associated_data = b"Kelompok15_Case3_DataProteksiMQTT"
    keys_dict = {
        16: b"KunciRahasia128B",                 # 128-bit
        24: b"KunciRahasia192BitPanjan",         # 192-bit
        32: b"KunciRahasia256BitPalingPanjang0"  # 256-bit
    }

    print("Algoritma | Kunci(Bits) | Pesan(Bytes) | Avg Transmission (Detik)")
    print("-" * 70)

    results = []

    for algo in ["AES-GCM", "ChaCha20", "Ascon-ECB"]:
        for key_size, key_bytes in keys_dict.items():
            for msg_size in message_sizes:

                total_delay = 0.0
                plaintext = generate_random_bytes(msg_size)

                # Pre-enkripsi untuk mendapatkan payload
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
                    ciphertext = ascon_ecb_encrypt(ascon_key, plaintext)
                    payload = ciphertext

                # Kirim 100 kali dan ukur transmission delay
                for _ in range(num_samples):
                    received_event.clear()
                    send_time = time.perf_counter()
                    client.publish(MQTT_TOPIC, payload, qos=0)

                    if received_event.wait(timeout=5.0):
                        delay = receive_time - send_time
                        total_delay += delay
                    else:
                        print(f"Timeout: {algo} ukuran {msg_size}!")
                        total_delay += 5.0

                avg_delay = total_delay / num_samples
                key_bits = key_size * 8

                print(f"{algo:<10} | {key_bits:<11} | {msg_size:<12} | {avg_delay:.5f}")
                results.append((algo, key_bits, msg_size, avg_delay))

    client.loop_stop()
    client.disconnect()

    with open("hasil_transmission_delay.csv", "w") as f:
        f.write("Algoritma,Ukuran_Kunci_Bits,Ukuran_Pesan_Bytes,Rata_Rata_Transmission_Detik\n")
        for res in results:
            f.write(f"{res[0]},{res[1]},{res[2]},{res[3]:.5f}\n")

    print("\n[SUKSES] Data disimpan di 'hasil_transmission_delay.csv'")

if __name__ == "__main__":
    benchmark_transmission()