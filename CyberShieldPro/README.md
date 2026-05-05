# 🛡️ CyberShieldPro v2.0

AI-asosida ishlaydi — Fishing hujumlarini aniqlash, interaktiv trening, real-time monitoring.

## 🚀 Ishga Tushirish

```bash
# 1. Virtual environment yarating
python -m venv .venv

# Windows
.venv\Scripts\activate

# Mac/Linux
source .venv/bin/activate

# 2. Kutubxonalarni o'rnating
pip install -r requirements.txt

# 3. Serverni ishga tushiring
python -m app.main

# 4. Brauzerda oching
# http://localhost:8000
```

## 📦 Modullar

| Modul | Tavsif |
|-------|--------|
| 🔍 Skaner | URL va Email fishing tahlili (20+ parametr) |
| 🎓 Trening | 5 ta interaktiv stsenariy, ball tizimi |
| 📊 Dashboard | Real-time grafik, jonli tahdid lenti |
| 🏆 Sertifikat | Treningdan so'ng sertifikat |

## 🔗 API Endpointlar

- `POST /api/scan/url` — URL skanerlash
- `POST /api/scan/email` — Email tahlil  
- `GET /api/training/scenarios` — Trening savollar
- `POST /api/training/submit` — Javob yuborish
- `GET /api/stats/dashboard` — Dashboard statistika
- `WS /ws/threats` — Real-time tahdidlar
