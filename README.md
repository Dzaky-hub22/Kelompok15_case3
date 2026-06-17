# Kelompok15_case3
source code untuk project_2
# fungsi code crypto_core.py
Kode Python tersebut adalah sebuah skrip benchmarking yang dirancang khusus untuk mengukur Computational Delay (waktu tunda komputasi) dari tiga algoritma kriptografi simetris: AES-GCM, ChaCha20, dan Ascon-128a.

Mengingat latar belakang pada bidang rekayasa dan pengujian keamanan siber, struktur kode ini dibangun dengan pendekatan komparatif berlapis (nested loops) yang sangat umum digunakan dalam evaluasi performa sistem.

Berikut adalah pembedahan fungsi kode tersebut baris demi baris:

1. Persiapan dan Fungsi Pendukung
Library Impor: Kode memuat time untuk perhitungan waktu presisi tinggi, secrets untuk menghasilkan string acak yang aman secara kriptografi, serta modul dari pycryptodome dan ascon sebagai mesin enkripsinya.

Fungsi generate_random_bytes: Fungsi ini bertugas menciptakan plaintext tiruan (dummy data). Penggunaan secrets.token_bytes memastikan data yang diuji memiliki entropi yang tinggi, mensimulasikan paket data riil yang dikirimkan melalui jaringan.

2. Deklarasi Parameter Eksperimen
Di dalam fungsi benchmark_cryptography(), beberapa variabel statis didefinisikan sebagai aturan main eksperimen:

message_sizes & num_samples: Menetapkan ukuran plaintext yang akan diuji (50 hingga 250 bytes) dan mewajibkan setiap pengujian diulang 100 kali untuk mendapatkan nilai rata-rata yang akurat.

associated_data: Teks konstan yang tidak dienkripsi tetapi ikut diautentikasi (khas pada mode AEAD - Authenticated Encryption with Associated Data).

keys_dict: Berisi tiga buah string yang dikalibrasi secara ketat agar panjang karakternya tepat 16, 24, dan 32 bytes. Hal ini sangat krusial karena algoritma block cipher akan langsung menghasilkan error jika ukuran kunci meleset 1 byte saja.

3. Jantung Eksekusi: Nested Loops
Kode ini menggunakan perulangan bersarang empat tingkat untuk mengotomatisasi seluruh skenario:

Memilih algoritma (AES-GCM, ChaCha20, Ascon-ECB).

Memilih ukuran kunci (128-bit, 192-bit, 256-bit).

Memilih ukuran pesan (50, 100, 150, 200, 250 bytes).

Menjalankan eksperimen 100 kali untuk kombinasi di atas.

4. Proses Enkripsi, Dekripsi, dan Pencatatan Waktu
Di dalam loop 100 sampel, skrip melakukan tahapan berikut untuk setiap algoritma:

time.perf_counter(): Fungsi ini dipanggil tepat sebelum enkripsi dimulai dan sesaat setelah dekripsi selesai. Ini adalah stopwatch internal Python yang mengukur waktu eksekusi CPU dalam satuan milidetik/mikrodetik tanpa terpengaruh oleh clock sistem operasi.

AES-GCM: Menginisialisasi cipher, memasukkan AD, mengenkripsi plaintext untuk menghasilkan ciphertext dan MAC tag, lalu langsung mendekripsinya menggunakan nonce yang sama.

ChaCha20: Karena library meminta panjang kunci spesifik (32 bytes), skrip melakukan trik padding (ljust) dengan menambahkan karakter null (\x00) pada kunci pengujian agar fungsi tidak menolak eksekusi.

Ascon-ECB: Mirip dengan ChaCha20, Ascon-128a memiliki aturan kaku di mana kunci dan nonce harus persis 16 bytes. Skrip memotong atau menambal string kunci agar sesuai dengan standar parameternya.

5. Akumulasi dan Ekspor Data
Waktu murni untuk mengeksekusi enkripsi dan dekripsi dikalkulasikan dengan mengurangkan end_time dengan start_time, lalu diakumulasikan ke variabel total_time.

Setelah 100 kali jalan, total waktu dibagi 100 (avg_delay = total_time / num_samples) untuk meniadakan anomali (misalnya jika CPU tiba-tiba mengalami spike dari aplikasi lain).

Pada akhirnya, semua rekaman data ini ditulis ke dalam berkas hasil_computational_delay.csv secara otomatis menggunakan blok with open(...), mempermudah pengolahan visualisasi matriks performa tanpa perlu melakukan penyalinan manual dari terminal.

# Fungsi code mqtt_transmission.py

Kode Python tersebut merupakan sebuah script pengujian jaringan (network benchmarking) yang secara spesifik dirancang untuk mengukur Transmission Delay dari payload terenkripsi saat dikirimkan melewati protokol MQTT.

Berbeda dengan skrip pertama yang hanya mengukur seberapa cepat CPU mengenkripsi pesan, skrip ini mensimulasikan perjalanan data secara nyata melalui infrastruktur internet publik menuju broker dan kembali lagi .

Berikut adalah penjelasan fungsional dari blok-blok kodenya:

1. Inisialisasi dan Konfigurasi Jaringan
paho.mqtt.client: Memuat library standar industri untuk implementasi protokol MQTT di Python.

MQTT_BROKER & MQTT_TOPIC: Kode ini diarahkan untuk melakukan koneksi ke broker.hivemq.com pada port 1883 (port standar MQTT unencrypted). Pendefinisian topik spesifik ("telkom/kelompok15/...") memastikan data eksperimen kalian tidak bercampur dengan lalu lintas publik lainnya.

2. Mekanisme Sinkronisasi Asinkron (Threading)
Poin ini adalah bagian paling krusial secara teknikal:

threading.Event(): Protokol MQTT berjalan secara asinkron (berjalan di background). Program utama tidak tahu kapan persisnya pesan balasan akan tiba. Objek Event ini bertindak sebagai "lampu lalu lintas".

Fungsi on_message: Saat program menerima pesan dari broker, fungsi callback ini otomatis tereksekusi. Ia seketika mencatat waktu kedatangan (receive_time) dan menyalakan lampu hijau (received_event.set()) untuk memberi tahu program utama bahwa satu siklus pengiriman telah selesai.

3. Persiapan Klien MQTT
Di dalam benchmark_transmission(), klien MQTT diinstansiasi, disambungkan ke callback on_connect dan on_message, lalu disambungkan ke internet menggunakan client.connect().

client.loop_start(): Ini memerintahkan library Paho untuk membuka sebuah thread (alur kerja) tersembunyi di background komputer kalian guna memantau lalu lintas jaringan secara terus-menerus tanpa membekukan (freeze) jalannya skrip utama.

4. Penyusunan Payload Kriptografi
Sebelum pesan dikirim, skrip meniru perilaku pengiriman riil:

Pembentukan payload: Pada AES-GCM, data yang dikirim (publish) via MQTT bukan hanya sekadar teks sandi (ciphertext). Agar penerima bisa mendekripsinya di dunia nyata, nonce dan MAC tag harus ikut dikirimkan. Oleh karena itu, skrip menggabungkannya menjadi payload = cipher_enc.nonce + tag + ciphertext. Hal serupa dilakukan untuk ChaCha20 dan Ascon (menggabungkan nonce + ciphertext).

5. Loop Pengukuran Transmisi Bolak-Balik (Round Trip)
Pengukuran dilakukan dalam looping 100 sampel. Di awal setiap loop, event trigger di-reset (received_event.clear()).

Waktu awal dicatat (send_time), lalu pesan ditembakkan ke internet menggunakan client.publish().

Sistem Timeout: Baris if received_event.wait(timeout=5.0): adalah jaring pengaman (safety net). Program utama akan menghentikan eksekusinya dan menunggu (maksimal 5 detik) hingga on_message memberikan sinyal hijau. Jika pesan sukses kembali dalam waktu kurang dari 5 detik, delay sejati dikalkulasikan (receive_time - send_time). Jika internet putus dan pesan hilang, sistem memunculkan peringatan Timeout dan mencatat penalti waktu agar program tidak hang selamanya.

6. Terminasi dan Ekspor
Setelah seluruh 1.500 paket data selesai diuji, client.loop_stop() menghentikan pemantauan background dan klien memutuskan koneksi secara elegan.

Sama seperti skrip pertama, hasil rata-rata per skenario dicatat dan diekspor ke dalam berkas hasil_transmission_delay.csv untuk memudahkan pembuatan visualisasi grafis performa jaringan.
