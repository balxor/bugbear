# Malware Analysis BankBot-YNRK - Android Banking Trojan

**Analyst**: Kenshin Himura of DTrust  
**Klasifikasi:** Android Banking Trojan  
**Family:** BankBot-YNRK  
**Skor:** 10/10  
**Tanggal Analisis:** 13 Juni 2026  
**Sample Hash:** `1ae0c4ffe18e7934c019ad1279219d1e8e8491bf62e8b34102e1497010c58247`

---

## 1. Informasi Sample

| Field | Value |
|---|---|
| **SHA256 (APK)** | `1ae0c4ffe18e7934c019ad1279219d1e8e8491bf62e8b34102e1497010c58247` |
| **SHA256 (ZIP)** | `c5d285d1d9c34aa099d06e4f4d1bb81316c7db2a0f4ca2e25a8c774d1c608528` |
| **MD5 (ZIP)** | `94bc4b95e82e0652ed0b1b208816406a` |
| **SHA1 (ZIP)** | `d098e7978e897ce792babb34a669699d44dad805` |
| **SSDEEP (APK)** | `393216:z8mDFD35UwceGPIlraPBS4feQxZRQ5OceDNmxtE+q` |
| **Ukuran APK** | 23.18 MB (24,303,738 bytes) |
| **Ukuran ZIP** | 14.69 MB (15,402,677 bytes) |
| **Tipe File** | Android APK, ARM64 + ARMv7 |
| **ZIP Enkripsi** | AES-256 (WinZip compression type 99) |
| **ZIP Password** | `infected` |
| **Package Name** | `com.un98apln.qingynrk298a` |
| **Sertifikat** | Self-signed, digest mismatch |

---

## 2. Ringkasan Eksekutif

BankBot-YNRK adalah Android banking trojan yang pertama kali dilaporkan oleh CYFIRMA pada November 2025. Sample ini (`com.un98apln.qingynrk298a`) ditemukan di MalwareBazaar dengan tag `Indonesia` pada Juni 2026. Varian lain dengan package name `com.westpacb4a.payqingynrk1b4a` dan `com.dfdcb.dfdcb` teridentifikasi di platform Tria.ge pada periode yang sama.

Aplikasi mengaku sebagai **Identitas Kependudukan Digital** - aplikasi resmi Ditjen Dukcapil Kemendagri RI (`gov.dukcapil.mobile_id`). Distribusi dilakukan melalui file ZIP terenkripsi AES yang berisi satu APK.

Malware menargetkan perangkat Android 13 ke bawah dan menggunakan kombinasi Accessibility Service abuse, overlay injection, keylogging, SMS interception, clipboard monitoring dan remote command execution untuk mencuri kredensial perbankan dan melakukan transaksi ilegal.

---

## 3. Static Analysis

### 3.1 Struktur APK

APK berisi 1,647 file entry dengan komposisi:

```
APK (23.18 MB)
├── classes.dex                         (6,475 KB)  - Kode Java/Kotlin ter-obfuscate
├── AndroidManifest.xml                 (21 KB)     - Binary XML format
├── resources.arsc                      (1,011 KB)  - Resource table
├── lib/
│   ├── arm64-v8a/
│   │   ├── libBugly_Native.so           (191 KB)   - Tencent Bugly crash reporting
│   │   ├── libimage_processing_util_jni.so (28 KB)
│   │   ├── libjingle_peerconnection_so.so (6,968 KB) - WebRTC peer connection
│   │   ├── libmmkv.so                   (700 KB)   - Tencent MMKV key-value storage
│   │   ├── libpl_droidsonroids_gif.so    (40 KB)   - GIF rendering
│   │   ├── libsls_producer.so           (806 KB)   - Alibaba Cloud SLS logging
│   │   └── libx2.so                     (258 KB)   - Custom native library
│   └── armeabi-v7a/
│       └── [tujuh library serupa, versi 32-bit]
├── O0O0O0/OOOO.gz                      (37 KB)    - Mozilla Public Suffix List (OkHttp)
├── META-INF/services/
│   ├── O0OOO0.OOOOOO   → O0OOoO.O0000
│   ├── O0OOo0.O0O000O  → O0OOoO.O000O
│   └── Oo0OoO.OO00O0O  → OoooO0.O00OO00 / OoooO0.O00OOO0 / OoooO0.O000OOO
├── com/google/api/client/googleapis/google.jks (70 KB) - Java KeyStore
├── okhttp3/internal/publicsuffix/       - OkHttp networking libraries
└── org/apache/commons/codec/            - Apache Commons Codec
```

Delegate komputasi sensitif ke native library (`libx2.so`, `libsls_producer.so`) adalah teknik menghindari deteksi berbasis DEX scanning.

### 3.2 Nama Komponen

Komponen yang terdaftar di AndroidManifest (diverifikasi via Tria.ge static analysis dan cross-check strings DEX):

| Tipe | Nama | Fungsi |
|---|---|---|
| **Activity** | `com.igg.andr.Launcher` | Entry point, intent MAIN/LAUNCHER |
| **Activity** | `com.igg.andr.MainActivity` | Alias ke `com.exam.remo.MainActivity` |
| **Activity** | `com.igg.andr.GoAppLauncher` | Launcher sekunder |
| **Activity** | `androidx.core.app.ui.CameraActivity` | Akses kamera |
| **Activity** | `androidx.core.app.ui.ScreenshotActivity` | Screen capture |
| **Activity** | `androidx.core.app.ui.AGPActivity` | Auto-generate page |
| **Activity** | `androidx.core.app.ui.AutoActivity` | Automation UI |
| **Activity** | `com.fanjun.keeplive.activity.OnePixelActivity` | Keep-alive 1-pixel window |
| **Activity** | `com.google.wall.view.ShellActivity` | Google News impersonation |
| **Service** | `com.anydesk.adcontrol.ControlService` | Accessibility Service handler |
| **Service** | `com.fanjun.keeplive.service.LocalService` | Keep-alive process 1 |
| **Service** | `com.fanjun.keeplive.service.RemoteService` | Keep-alive process 2 |
| **Service** | `com.fanjun.keeplive.service.HideForegroundService` | Foreground persistence |
| **Service** | `com.fanjun.keeplive.service.JobHandlerService` | JobScheduler handler |
| **Service** | `androidx.core.app.FS` | Foreground service generic |
| **Service** | `androidx.camera.core.impl.MetadataHolderService` | Camera metadata |
| **Receiver** | `androidx.service.DeviceReceiver` | Device Admin + BOOT_COMPLETED |
| **Receiver** | `com.fanjun.keeplive.receiver.NotificationClickReceiver` | Re-launch via notifikasi |
| **Receiver** | `androidx.profileinstaller.ProfileInstallReceiver` | Profile installer |
| **Provider** | `androidx.core.content.FileProvider` | File sharing |
| **Provider** | `androidx.startup.InitializationProvider` | App startup |
| **Provider** | `com.aliyun.sls.android.producer.provider.SLSContentProvider` | Alibaba Cloud SLS exfiltration |

### 3.3 Permission

| Permission | Risiko |
|---|---|
| `INTERNET` | C2 communication |
| `SYSTEM_ALERT_WINDOW` | Overlay attack (fake login screen) |
| `BIND_ACCESSIBILITY_SERVICE` | Keylogging, auto-click, UI traversal |
| `BIND_DEVICE_ADMIN` | Anti-uninstall, remote lock/wipe |
| `READ_SMS`, `SEND_SMS` | OTP interception |
| `READ_CONTACTS` | Contact harvesting |
| `READ_PHONE_STATE`, `READ_PHONE_NUMBERS` | Device fingerprinting |
| `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION` | GPS tracking |
| `CAMERA` | Remote camera capture |
| `CALL_PHONE` | Unauthorized calls |
| `RECEIVE_BOOT_COMPLETED` | Persistensi setelah restart |
| `REQUEST_INSTALL_PACKAGES` | Self-update / dropper |
| `QUERY_ALL_PACKAGES` | Reconnaissance installed apps |
| `FOREGROUND_SERVICE` + `*_MEDIA_PROJECTION` | Screen recording |
| `MANAGE_EXTERNAL_STORAGE`, `READ/WRITE_EXTERNAL_STORAGE` | File exfiltration |
| `DISABLE_KEYGUARD` | Bypass lock screen |
| `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | Mencegah Doze kill |
| `WRITE_SETTINGS` | Modify system settings |

### 3.4 Analisis DEX

File `classes.dex` berukuran 6,475 KB (6.3 MB). Pencarian string ASCII menghasilkan temuan berikut:

**C2 WebSocket**

```
wss://ping.ynmvsw.top:8989
```

Komunikasi C2 menggunakan WebSocket Secure pada port non-standar 8989. CYFIRMA sebelumnya melaporkan domain berbeda (`ping.ynrkone[.]top`), yang menunjukkan aktor mengoperasikan multiple C2 domain secara paralel.

**Target aplikasi finansial**

```
com.gojek.gopay              - GoPay (Indonesia)
com.jago.digital             - Bank Jago (Indonesia)
com.binance.dev              - Binance (crypto exchange)
com.gateio.walletslib.*      - Gate.io (crypto wallet)
com.vietinbank.ipay          - VietinBank iPay (Vietnam)
com.vnpay.bidv               - BIDV SmartBanking (Vietnam)
com.vnpay.vpbankonline       - VPBank Online (Vietnam)
```

Tujuh package name teridentifikasi di plaintext DEX. CYFIRMA melaporkan ada 62 aplikasi finansial dalam daftar target. Package name yang tersisa kemungkinan disimpan dalam bentuk terenkripsi di `libx2.so` atau diunduh saat runtime dari C2.

**URL pihak ketiga**

```
https://aria.laoyuyu.me/aria_doc/         - Dokumentasi library Aria downloader (developer tool)
https://android.bugly.qq.com/rqd/async     - Tencent Bugly crash report endpoint
```

### 3.5 Analisis Native Library

| Library | Ukuran | Fungsi |
|---|---|---|
| `libsls_producer.so` | 806 KB | Alibaba Cloud Simple Log Service producer - exfiltrasi data ke `sls.aliyun.com` |
| `libx2.so` | 258 KB | Library kustom - tidak cocok dengan library open-source manapun. Kemungkinan penyimpan konfig terenkripsi, C2 address encoding, atau payload stage-2 |
| `libjingle_peerconnection_so.so` | 6,968 KB | WebRTC (Google Jingle) - dugaan untuk AnyDesk remote control tersembunyi atau P2P C2 fallback |
| `libBugly_Native.so` | 191 KB | Tencent Bugly - crash diagnostics & device fingerprinting |
| `libmmkv.so` | 700 KB | Tencent MMKV - high-performance key-value store, digunakan untuk persistensi konfig malware |
| `libpl_droidsonroids_gif.so` | 40 KB | Library GIF - kemungkinan untuk animasi fake loading screen overlay |

### 3.6 File O0O0O0/OOOO.gz

File GZIP 37 KB (`1f8b` magic) setelah dekompresi menghasilkan 104 KB data teks. Kontennya adalah Mozilla Public Suffix List - daftar domain publik yang digunakan oleh library OkHttp untuk cookie domain matching. File ini adalah dependensi standar OkHttp, bukan konfigurasi malware.

### 3.7 Obfuscation

Class name menggunakan pola `O0` dan `Oo` yang khas dari ProGuard/R8 dengan konfigurasi `-obfuscationdictionary`. File META-INF/services mendaftarkan service implementation class yang nama-namanya di-obfuscate:

```
O0OOO0.OOOOOO → O0OOoO.O0000
O0OOo0.O0O000O → O0OOoO.O000O
Oo0OoO.OO00O0O → OoooO0.O00OO00, OoooO0.O00OOO0, OoooO0.O000OOO
```

AndroidManifest.xml disimpan dalam format binary XML (header `03000800`), tidak terbaca langsung sebagai plaintext.

---

## 4. Infrastruktur C2

| Domain | Port | Protokol | Sumber |
|---|---|---|---|
| `wss://ping.ynmvsw.top` | 8989 | WebSocket Secure | Ditemukan di classes.dex |
| `ping.ynrkone[.]top` | - | HTTP/HTTPS | Laporan CYFIRMA (Nov 2025) |
| `sls.aliyun.com` | 443 | HTTPS (Alibaba Cloud SLS) | `libsls_producer.so` + ContentProvider |

Aktor menggunakan WebSocket untuk komunikasi real-time dua arah. Port 8989 non-standar. Alibaba Cloud SLS berfungsi sebagai kanal exfiltrasi data sekaligus log storage.

---

## 5. Mekanisme Serangan

### 5.1 Distribusi

APK dikemas dalam ZIP AES-256 encrypted dengan password `infected`. Dari laporan CYFIRMA, APK diberi nama `IdentitasKependudukanDigital.apk` untuk meniru aplikasi Dukcapil.

### 5.2 Anti-Analisis

- **Virtualization/Sandbox Evasion (T1633.001)**: Pengecekan environment emulator/VM sebelum payload aktif. Malware tidak aktif jika mendeteksi environment analisis.
- **Device-specific targeting**: Pengecekan Oppo/ColorOS, Samsung, Google Pixel. Device di luar whitelist tidak menerima payload secara penuh.
- **Download New Code at Runtime (T1407)**: DEX tambahan diunduh dari C2. Tria.ge mendeteksi `Loads dropped Dex/Jar`.

### 5.3 Persistensi

- **Foreground Persistence (T1541)**: Service berjalan sebagai foreground service dengan notifikasi palsu "IKD Service berjalan"
- **Scheduled Task/Job (T1603)**: JobScheduler menjalankan task periodik setiap 15 menit; BOOT_COMPLETED receiver memulai service saat perangkat reboot
- **Prevent Application Removal (T1629.001)**: Device Admin memblokir tombol Uninstall; dual-process keep-alive (`LocalService` + `RemoteService`) saling restart jika salah satu di-kill
- **Battery Optimization Bypass**: `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` mencegah Doze mematikan service

### 5.4 Credential Access

- **Input Capture - Keylogging (T1417.001)**: Accessibility Service mencatat setiap keystroke
- **Input Capture - GUI Input Capture (T1417.002)**: Overlay injection - saat korban membuka aplikasi target (GoPay, Jago, dll), malware menampilkan window login palsu di atas aplikasi asli
- **Clipboard Data (T1414)**: Clipboard monitor membaca data yang di-copy pengguna
- **Protected User Data - SMS Messages (T1636.004)**: Membaca semua SMS masuk, termasuk OTP perbankan
- **Protected User Data - Contact List (T1636.003)**: Membaca seluruh kontak
- **Screen Capture (T1513)**: Screenshot dan screen recording UI aplikasi perbankan

### 5.5 Exfiltration

Data dikirim melalui dua kanal:

1. **Alibaba Cloud SLS** via `libsls_producer.so` dan `SLSContentProvider`
2. **WebSocket C2** via `wss://ping.ynmvsw.top:8989`

### 5.6 Volume Muting

Saat pertama kali dijalankan, malware mengatur volume stream `STREAM_MUSIC`, `STREAM_RING` dan `STREAM_NOTIFICATION` ke 0. Hal ini menyebabkan korban tidak mendengar panggilan masuk, SMS dan notifikasi, sehingga tidak menyadari transaksi ilegal.

---

## 6. Varian Terkait

| Package Name | Impersonasi | Pertama Terlihat | Hash (APK) |
|---|---|---|---|
| `com.westpacb4a.payqingynrk1b4a` | Identitas Kependudukan Digital | Sep 2025 | `cb25b1664a856f0c3e71a318f3e35eef8b331e047acaf8c53320439c3c23ef7c` |
| `com.westpacf78.payqingynrk1f78` | Identitas Kependudukan Digital | Sep 2025 | - |
| `com.westpac91a.payqingynrk191a` | Identitas Kependudukan Digital | Sep 2025 | - |
| `com.dfdcb.dfdcb` | VSSID (BPJS Vietnam) | Mei 2026 | `0985478ccbf4641ca5117abb985bc33a269008a5d5641ef9b2d30e8ae0570703` |
| `com.un98apln.qingynrk298a` | Tidak spesifik | Jun 2026 | `1ae0c4ffe18e7934c019ad1279219d1e8e8491bf62e8b34102e1497010c58247` |

Semua varian menggunakan codebase yang sama dengan perbedaan pada package name, resource overlay dan daftar target aplikasi. Template nama package mengikuti pola `com.[prefix].[prefix]ynrk[suffix]`.

---

## 7. MITRE ATT&CK Mobile Mapping

| Tactic | Technique | ID |
|---|---|---|
| **Execution** | Scheduled Task/Job | T1603 |
| **Persistence** | Foreground Persistence | T1541 |
| **Persistence** | Scheduled Task/Job | T1603 |
| **Defense Evasion** | Download New Code at Runtime | T1407 |
| **Defense Evasion** | Foreground Persistence | T1541 |
| **Defense Evasion** | Hide Artifacts - User Evasion | T1628.002 |
| **Defense Evasion** | Impair Defenses - Prevent Application Removal | T1629.001 |
| **Defense Evasion** | Input Injection | T1516 |
| **Defense Evasion** | Virtualization/Sandbox Evasion - System Checks | T1633.001 |
| **Credential Access** | Clipboard Data | T1414 |
| **Credential Access** | Input Capture - Keylogging | T1417.001 |
| **Credential Access** | Input Capture - GUI Input Capture | T1417.002 |
| **Discovery** | Process Discovery | T1424 |
| **Discovery** | System Information Discovery | T1426 |
| **Discovery** | System Network Configuration Discovery | T1422 |
| **Discovery** | System Network Connections Discovery | T1421 |
| **Collection** | Clipboard Data | T1414 |
| **Collection** | Input Capture - Keylogging | T1417.001 |
| **Collection** | Input Capture - GUI Input Capture | T1417.002 |
| **Collection** | Protected User Data - Contact List | T1636.003 |
| **Collection** | Protected User Data - SMS Messages | T1636.004 |
| **Collection** | Screen Capture | T1513 |
| **C2** | Web Service | T1102 |
| **Impact** | Data Manipulation - Transmitted Data Manipulation | T1641.001 |
| **Impact** | Input Injection | T1516 |

---

## 8. Indicators of Compromise (IOC)

### 8.1 Hash

```
# Sample utama (APK)
SHA256: 1ae0c4ffe18e7934c019ad1279219d1e8e8491bf62e8b34102e1497010c58247
MD5:    3e81ee4d89ef7443542b1a3eb1e4fbec
SHA1:   5fab18a55c57b2419d88ce68e213396e7892587c

# ZIP container
SHA256: c5d285d1d9c34aa099d06e4f4d1bb81316c7db2a0f4ca2e25a8c774d1c608528
MD5:    94bc4b95e82e0652ed0b1b208816406a

# Varian CYFIRMA (com.westpacb4a)
SHA256: cb25b1664a856f0c3e71a318f3e35eef8b331e047acaf8c53320439c3c23ef7c

# Varian VSSID (com.dfdcb)
SHA256: 0985478ccbf4641ca5117abb985bc33a269008a5d5641ef9b2d30e8ae0570703
```

### 8.2 Domain & Network

```
wss://ping.ynmvsw.top:8989
ping.ynrkone[.]top
sls.aliyun.com
```

### 8.3 Package Names

```
com.un98apln.qingynrk298a
com.westpacb4a.payqingynrk1b4a
com.westpacf78.payqingynrk1f78
com.westpac91a.payqingynrk191a
com.dfdcb.dfdcb
```

### 8.4 Sertifikat

```
CN=dpt, OU=dpt, O=dpt (sample VSSID)
Self-signed, digest mismatch (sample utama)
```

### 8.5 Nama File Distribusi

```
IdentitasKependudukanDigital.apk
VSSID.apk
DichVuCong.apk
1ae0c4ffe18e7934c019ad1279219d1e8e8491bf62e8b34102e1497010c58247.apk
```

---

## 9. Code Authorship Analysis

### 9.1 Obfuscation Tool: `nmm-protect`

CYFIRMA mendeteksi package `nmm-protect` dalam APK hasil dekompilasi. `nmm-protect` adalah framework obfuscation komersial dari China, tidak tersedia secara open-source dan didistribusikan melalui forum developer China serta marketplace tertutup. Developer di luar ekosistem China menggunakan ProGuard, DexGuard, atau R8.

### 9.2 Watermark Developer: `qing` + `ynrk`

Prefix `qing` muncul konsisten di setiap varian package name:

```
com.westpacb4a.payqingynrk1b4a
com.westpacf78.payqingynrk1f78
com.westpac91a.payqingynrk191a
com.un98apln.qingynrk298a
```

"Qing" (青, 清, 庆, 晴, 情, 卿) adalah suku kata nama pribadi yang sangat umum di China. Developer menyisipkan nama panggilan sebagai watermark. `ynrk` tidak memiliki arti dalam bahasa Mandarin, Vietnam, Indonesia, atau Inggris - kemungkinan singkatan atau string acak yang berfungsi sebagai family identifier.

### 9.3 Ekosistem Tencent

APK mengandung dua library native Tencent:

| Library | Ukuran | Fungsi |
|---|---|---|
| `libBugly_Native.so` | 191 KB | Crash reporting + device fingerprinting |
| `libmmkv.so` | 700 KB | Key-value storage performa tinggi |

Tencent Bugly adalah layanan crash reporting yang digunakan secara eksklusif oleh developer China. Tencent MMKV digunakan oleh aplikasi China populer seperti WeChat dan QQ. Developer di luar China menggunakan Firebase Crashlytics dan SharedPreferences/DataStore.

### 9.4 Alibaba Cloud SLS

```
libsls_producer.so (806 KB)
com.aliyun.sls.android.producer.provider.SLSContentProvider
```

Alibaba Cloud Simple Log Service adalah kanal exfiltrasi data. SLS hampir tidak digunakan di luar ekosistem developer China. Developer dari luar China memilih AWS CloudWatch, GCP Cloud Logging, atau Azure Monitor.

### 9.5 Downloader Aria

DEX berisi referensi ke `https://aria.laoyuyu.me/aria_doc/`. Aria adalah library download manager Android yang populer di kalangan developer China. Domain `laoyuyu.me` ("Lao Yu Yu" / 老鱼鱼) adalah nickname personal developer China.

### 9.6 Toolchain

| Komponen | Asal | Alternatif Global |
|---|---|---|
| Obfuscation | `nmm-protect` (China) | ProGuard, DexGuard |
| Crash diagnostics | Tencent Bugly (China) | Firebase Crashlytics |
| KV storage | Tencent MMKV (China) | SharedPreferences, DataStore |
| Exfiltration | Alibaba Cloud SLS (China) | AWS CloudWatch, GCP |
| Downloader | Aria (China) | OkHttp Download, Fetch2 |
| P2P | Janus WebRTC (Open-source) | - |

Empat dari lima tool spesifik-negara berasal dari China.

### 9.7 Target Apps per Negara

Daftar 62 aplikasi finansial dikirim langsung oleh C2 ke infected device:

| Negara | Jumlah | Contoh Aplikasi |
|---|---|---|
| Vietnam | 21 | MoMo, VCB Digibank, VPBank NEO, Techcombank, Agribank, BIDV, MB Bank, VietinBank, ZaloPay |
| Indonesia | 17 | BCA Mobile, Livin' by Mandiri, BRImo, BNI Mobile, CIMB Niaga, SeaBank, Jenius, PermataBank, BTN, Bank Jatim, Muamalat, BSI, Panin, BRILink, Bank NEO |
| Malaysia | 10 | Maybank2u, CIMB Clicks, Public Bank, RHB, Hong Leong Connect, Ambank, Affin, Alliance, UOB Malaysia, Bank Islam |
| India | 6 | SBI Yono, ICICI iMobile, HDFC MobileBanking, AXIS Mobile, Bank of Baroda m-Connect, Kotak Mahindra |
| Singapura | 2 | DBS digibank, OCBC OneMobile |
| Crypto wallets | 16 | Exodus, MetaMask, Trust Wallet, Coinomi, SafePal, Coin98, BitKeep, imToken, TokenPocket, Krystal |

Tidak satu pun target berasal dari China. Tidak ada ICBC, Alipay, WeChat Pay, atau China Merchants Bank.

### 9.8 Lokalisasi UI Phishing

Overlay pada varian Indonesia menampilkan teks: "**Verifikasi Data Pribadi.** Data Anda sedang diverifikasi... Mohon tunggu, jangan tutup aplikasi." (Bahasa Indonesia natural, dikonfirmasi dari screenshot CYFIRMA). Varian Vietnam menggunakan impersonasi VSSID (`VSSID.apk`) dan DichVuCong (`DichVuCong.apk`).

---

## 10. Attribution Assessment & Operational Model

### 10.1 Model Operasi

BankBot-YNRK beroperasi dalam model Malware-as-a-Service (MaaS). DeliveryRAT - Android trojan dengan codebase dan infrastruktur yang tumpang-tindih - diiklankan melalui Telegram bot "Bonvi Team." Satu developer utama membangun core engine dan memelihara infrastruktur C2. Afiliasi per negara membeli akses, menyesuaikan skin phishing dalam bahasa lokal dan mendistribusikan APK ke target.

```
DEVELOPER UTAMA (Chinese-speaking)
├── Bangun core engine BankBot-YNRK
├── Maintain C2 infrastructure (chat room model)
├── Bundle dengan toolchain: nmm-protect, Tencent Bugly/MMKV, Alibaba SLS, Aria
├── Jual/sewa via Telegram bot "Bonvi Team"
├── Sediakan template overlay dan daftar target
│
├── AFILIASI INDONESIA
│   ├── Impersonasi: Dukcapil IKD Digital
│   ├── Overlay: "Verifikasi Data Pribadi" dalam Bahasa Indonesia
│   ├── Target: 17 bank + GoPay + Bank Jago
│   └── Distribusi: WhatsApp/SMS/Telegram ke nomor Indonesia
│
├── AFILIASI VIETNAM
│   ├── Impersonasi: VSSID, DichVuCong
│   ├── Overlay: dalam Bahasa Vietnam
│   ├── Target: 21 bank + MoMo + ZaloPay
│   └── Distribusi: Zalo/SMS ke nomor Vietnam
│
├── AFILIASI MALAYSIA
│   ├── Target: 10 bank (Maybank, CIMB, Public Bank, dsb.)
│   └── Distribusi: WhatsApp/Telegram
│
└── AFILIASI INDIA
    ├── Target: 6 bank (SBI, ICICI, HDFC, AXIS, Bank of Baroda, Kotak)
    └── Distribusi: WhatsApp
```

### 10.2 Infrastruktur C2

Selain `wss://ping.ynmvsw.top:8989` dan `ping.ynrkone[.]top:8181`, CYFIRMA mengidentifikasi tiga domain WebView loader yang digunakan untuk mengunduh konten phishing:

```
plp.foundzd.vip     (specimen 1)
plp.e1in2.top       (specimen 2)
plp.en1inei2.top    (specimen 3)
```

`.top` adalah TLD termurah yang didominasi registrar China (Alibaba Cloud, West.cn). `.vip` populer di kalangan operator kriminal Asia. C2 beroperasi dalam model "chat room": satu handler otomatis melayani semua infected device. Setiap device mengirim device ID + daftar aplikasi terinstal, C2 merespons dengan daftar target yang sesuai.

### 10.3 Motif

| Faktor | Evidence |
|---|---|
| Motif | Murni finansial - 62 target semuanya bank/wallet/kripto. Tidak ada target pemerintah, militer, diplomatik |
| Multi-negara | Indonesia, Vietnam, Malaysia, India, Singapura - tidak ada pola geopolitik. Pattern kriminal: negara dengan pasar mobile banking besar + regulasi longgar |
| Model bisnis | MaaS dijual via Telegram bot terbuka. APT tidak menjual malware di marketplace publik |
| Infrastruktur | Domain `.top` murah, self-signed cert, Alibaba Cloud free/public tier |
| MITRE ATT&CK | Tidak terdaftar di bawah grup APT oleh MITRE, Mandiant, CrowdStrike, atau vendor threat intel manapun |
| Espionage capability | Tidak ada keylogger sistem, screen capture OS-level, exfil dokumen/excel/pdf. Fokus eksklusif pada field input perbankan via A11Y |
| Destructive capability | Tidak ada ransomware module, wiper, atau data destruction |
| Lateral movement | Tidak ada modul untuk menyebar ke jaringan internal |

### 10.4 Assessment Final

Developer utama BankBot-YNRK adalah programmer Android dengan kemampuan bahasa Mandarin, familiar dengan toolchain developer China (Tencent, Alibaba, `nmm-protect`, Aria). Watermark `qing` di package name menunjukkan nama panggilan personal. Target spread murni ASEAN + India tanpa menyentuh bank China - pola menghindari penegak hukum domestik.

Operasi berjalan dalam model MaaS multi-afiliasi: satu codebase, banyak skin phishing per negara, distribusi per negara oleh aktor yang berbeda namun terhubung ke infrastruktur C2 yang sama. Aktor mengarah ke kelompok cybercriminal Asia Tenggara dengan developer utama Chinese-speaking.

---

## 11. Deteksi

### 11.1 Indikator Infeksi Perangkat

- Volume perangkat tiba-tiba 0 dan tidak dapat dinaikkan
- Aplikasi "IKD Service" atau nama generik mencurigakan di Settings → Apps, bukan dari Play Store
- Ikon aplikasi hilang dari launcher
- Notifikasi "IKD Service berjalan" yang persisten
- Device Admin dengan nama `androidx.service.DeviceReceiver` di Settings → Security
- Accessibility Service dengan nama `ControlService` atau `com.anydesk.adcontrol` di Settings → Accessibility

### 11.2 YARA Rule

```yara
rule BankBot_YNRK_Android {
    meta:
        author = "Malware Analysis Research"
        description = "Detects BankBot-YNRK Android banking trojan"
        date = "2026-06-16"
        family = "BankBot_YNRK"
        hash = "1ae0c4ffe18e7934c019ad1279219d1e8e8491bf62e8b34102e1497010c58247"
        reference = "https://tria.ge/260615-xx2dlsew9w"
    strings:
        $pkg1 = "com.westpac" ascii
        $pkg2 = "com.un98apln" ascii
        $pkg3 = "com.dfdcb.dfdcb" ascii
        $c2_1 = "ynmvsw.top" ascii
        $c2_2 = "ynrkone" ascii
        $a11y = "com.anydesk.adcontrol.ControlService" ascii
        $exfil = "com.aliyun.sls.android.producer" ascii
        $keep = "com.fanjun.keeplive" ascii
        $sink = "com.google.wall.view.ShellActivity" ascii
    condition:
        uint32(0) == 0xc01b3d04 and   // ZIP/APK magic
        (1 of ($pkg*) or $c2_1 or $c2_2) and
        2 of ($a11y, $exfil, $keep, $sink)
}
```

---

## 12. Mitigasi

1. Hanya menginstal aplikasi dari Google Play Store. Nonaktifkan "Install unknown apps" di Settings.
2. Verifikasi developer aplikasi: aplikasi Dukcapil resmi memiliki package name `gov.dukcapil.mobile_id` dan developer "Direktorat Jenderal Kependudukan dan Pencatatan Sipil."
3. Periksa Settings → Accessibility secara berkala. Nonaktifkan service yang tidak dikenal.
4. Periksa Settings → Security → Device Administrators. Nonaktifkan admin yang tidak dikenal.
5. Perbarui Android ke versi 14 atau lebih baru. Android 14 memblokir Accessibility Service abuse untuk permission escalation.
6. Pantau volume perangkat sebagai indikator awal infeksi.

---

## 13. Referensi

1. CYFIRMA, "Investigation Report: Android BankBot-YNRK Mobile Banking Trojan," 29 Oktober 2025.  
2. The Hacker News, "Researchers Uncover BankBot-YNRK and DeliveryRAT Android Trojans Stealing Financial Data," 3 November 2025.  
3. MalwareBazaar, tag `Indonesia`, diakses 13 Juni 2026.  
