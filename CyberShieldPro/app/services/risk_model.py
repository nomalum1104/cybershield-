import re
import math
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, List, Tuple

PHISHING_KEYWORDS = [
    "zudlik bilan", "darhol", "urgent", "immediate", "verify now",
    "account suspended", "click here", "confirm identity", "limited time",
    "winner", "congratulations", "free gift", "act now", "expires",
    "login immediately", "verify your account", "unusual activity",
    "security alert", "password expired", "update payment",
    "tasdiqla", "hisobingiz", "shoshilinch", "muddati tugaydi"
]

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.link']

LEGITIMATE_DOMAINS = [
    'google.com', 'gmail.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'facebook.com', 'instagram.com', 'twitter.com', 'paypal.com', 'ebay.com',
    'gov.uz', 'uzb.uz', 'myid.uz'
]

HOMOGRAPH_PAIRS = [
    ('0', 'o'), ('1', 'l'), ('rn', 'm'), ('vv', 'w'),
    ('paypa1', 'paypal'), ('arnazon', 'amazon'), ('g00gle', 'google'),
    ('micros0ft', 'microsoft'), ('facebok', 'facebook')
]


def analyze_url(url: str) -> Dict:
    score = 0
    indicators = []
    recommendations = []

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        scheme = parsed.scheme

        # HTTP vs HTTPS
        if scheme == 'http':
            score += 20
            indicators.append({
                "type": "danger",
                "icon": "🔓",
                "text": "HTTP protokoli - shifrsiz ulanish",
                "detail": "HTTPS ishlatilmagan, ma'lumotlar ochiq uzatiladi"
            })
        else:
            indicators.append({
                "type": "safe",
                "icon": "🔒",
                "text": "HTTPS shifrlash mavjud",
                "detail": "SSL sertifikat bor"
            })

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 30
                indicators.append({
                    "type": "danger",
                    "icon": "⚠️",
                    "text": f"Shubhali domen kengaytmasi: {tld}",
                    "detail": "Bu TLD ko'pincha fishing saytlar tomonidan ishlatiladi"
                })

        # IP address instead of domain
        ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.match(domain):
            score += 35
            indicators.append({
                "type": "danger",
                "icon": "🚨",
                "text": "Domen o'rniga IP manzil",
                "detail": "Haqiqiy saytlar odatda IP manzil ishlatmaydi"
            })

        # Homograph attacks
        for fake, real in HOMOGRAPH_PAIRS:
            if fake in domain and real not in domain:
                score += 40
                indicators.append({
                    "type": "danger",
                    "icon": "🎭",
                    "text": f"Homograf hujumi: '{fake}' → '{real}' o'xshatmoqda",
                    "detail": "Asl sayt nomiga o'xshash soxta domen"
                })

        # Subdomain abuse
        subdomains = domain.split('.')
        if len(subdomains) > 3:
            score += 15
            indicators.append({
                "type": "warning",
                "icon": "⚡",
                "text": f"Haddan ko'p subdomenlar: {len(subdomains) - 2} ta",
                "detail": "Ko'p subdomen qo'shish orqali asl domenni yashirish urinishi"
            })

        # Legitimate domain in path/subdomain (not actual domain)
        for legit in LEGITIMATE_DOMAINS:
            legit_base = legit.split('.')[0]
            if legit_base in domain and not domain.endswith(legit):
                score += 25
                indicators.append({
                    "type": "danger",
                    "icon": "🎪",
                    "text": f"'{legit}' nomi soxta domendan topildi",
                    "detail": f"Haqiqiy '{legit}' emas, balki uni taqlid qilmoqda"
                })
                break

        # Long URL
        if len(url) > 100:
            score += 10
            indicators.append({
                "type": "warning",
                "icon": "📏",
                "text": f"Juda uzun URL: {len(url)} belgi",
                "detail": "Fishing saytlar ko'pincha murakkab, uzun URLlar ishlatadi"
            })

        # URL shorteners
        shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'short.link']
        for shortener in shorteners:
            if shortener in domain:
                score += 15
                indicators.append({
                    "type": "warning",
                    "icon": "🔗",
                    "text": "URL qisqartirish xizmati ishlatilgan",
                    "detail": "Haqiqiy manzilni yashirish uchun ishlatilishi mumkin"
                })

        # Suspicious path keywords
        suspicious_paths = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'banking']
        for sp in suspicious_paths:
            if sp in path:
                score += 5
                indicators.append({
                    "type": "warning",
                    "icon": "📂",
                    "text": f"Shubhali yo'l: '/{sp}'",
                    "detail": "Login/verify so'zlari fishing saytlarda keng tarqalgan"
                })
                break

        # Recommendations
        if score < 20:
            recommendations = [
                "URL xavfsiz ko'rinadi",
                "Baribir shaxsiy ma'lumot kiritishdan ehtiyot bo'ling",
                "Sayt haqiqiy ekanligini tekshiring"
            ]
        elif score < 50:
            recommendations = [
                "Bu URLga ehtiyotkorlik bilan yondashing",
                "Shaxsiy yoki moliyaviy ma'lumot kiritmang",
                "Asl sayt URL sini alohida brauzerda kiriting",
                "Sayt sertifikatini tekshiring"
            ]
        else:
            recommendations = [
                "Bu URL XAVFLI - hech narsa kiritmang!",
                "Sahifani yoping va o'chirib tashlang",
                "Agar kiritgan bo'lsangiz - parolingizni o'zgartiring",
                "Bank yoki xizmatni rasmiy raqam orqali chaqiring"
            ]

    except Exception as e:
        score = 50
        indicators.append({
            "type": "warning",
            "icon": "❓",
            "text": "URL tahlil qilishda xato",
            "detail": str(e)
        })

    score = min(score, 100)
    risk_level = "XAVFSIZ" if score < 25 else "SHUBHALI" if score < 60 else "XAVFLI"
    risk_color = "green" if score < 25 else "yellow" if score < 60 else "red"

    return {
        "score": score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "indicators": indicators,
        "recommendations": recommendations,
        "analyzed_at": datetime.now().isoformat()
    }


def analyze_email(text: str) -> Dict:
    score = 0
    indicators = []
    recommendations = []
    text_lower = text.lower()

    # Phishing keywords
    found_keywords = []
    for keyword in PHISHING_KEYWORDS:
        if keyword.lower() in text_lower:
            found_keywords.append(keyword)
            score += 8

    if found_keywords:
        indicators.append({
            "type": "danger",
            "icon": "🚨",
            "text": f"Fishing so'zlari topildi: {len(found_keywords)} ta",
            "detail": f"Topilgan so'zlar: {', '.join(found_keywords[:5])}"
        })

    # Urgency patterns
    urgency_patterns = [
        r'\b24\s*soat\b', r'\b48\s*hour', r'asap', r'immediately',
        r'expires?\s+in', r'limited\s+time', r'act\s+now'
    ]
    urgency_found = sum(1 for p in urgency_patterns if re.search(p, text_lower))
    if urgency_found:
        score += urgency_found * 12
        indicators.append({
            "type": "danger",
            "icon": "⏰",
            "text": "Shoshilinch til ishlatilgan",
            "detail": "Fishing xabarlar odatda vaqt bosimi yaratib aldaydi"
        })

    # URLs in email
    urls = re.findall(r'https?://[^\s<>"]+', text)
    if urls:
        indicators.append({
            "type": "info",
            "icon": "🔗",
            "text": f"Email ichida {len(urls)} ta URL topildi",
            "detail": "URLlarni alohida tekshiring"
        })
        for url in urls[:3]:
            url_result = analyze_url(url)
            if url_result['score'] > 30:
                score += 15
                indicators.append({
                    "type": "danger",
                    "icon": "🌐",
                    "text": f"Shubhali URL: {url[:50]}...",
                    "detail": f"Risk score: {url_result['score']}%"
                })

    # Suspicious attachments mention
    attachment_keywords = ['.exe', '.zip', '.rar', 'fayl yuklang', 'attachment', 'download']
    for kw in attachment_keywords:
        if kw in text_lower:
            score += 15
            indicators.append({
                "type": "danger",
                "icon": "📎",
                "text": "Shubhali fayl/qo'shimcha eslatmasi",
                "detail": "Noma'lum fayllarni hech qachon yuklab olmang"
            })
            break

    # Personal info requests
    info_patterns = ['kredit karta', 'credit card', 'parol', 'password', 'pin kod', 'ssn', 'passport']
    for pattern in info_patterns:
        if pattern in text_lower:
            score += 20
            indicators.append({
                "type": "danger",
                "icon": "🔑",
                "text": "Shaxsiy ma'lumot so'ralmoqda",
                "detail": f"'{pattern}' so'zi topildi - haqiqiy xizmatlar bu ma'lumotlarni emailda so'ramaydi"
            })
            break

    # Sender address check
    email_pattern = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', text)
    if email_pattern:
        for email in email_pattern:
            domain = email.split('@')[1].lower()
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    score += 25
                    indicators.append({
                        "type": "danger",
                        "icon": "📧",
                        "text": f"Shubhali jo'natuvchi domen: {domain}",
                        "detail": "Fishing domenlar ko'pincha bepul domenlar ishlatadi"
                    })

    # Grammar/spelling issues simulation
    typo_indicators = ['clck', 'logn', 'verfiy', 'acount', 'pasword', 'urgant']
    typos_found = [t for t in typo_indicators if t in text_lower]
    if typos_found:
        score += len(typos_found) * 5
        indicators.append({
            "type": "warning",
            "icon": "📝",
            "text": "Yozuv xatolari aniqlandi",
            "detail": "Fishing xabarlar ko'pincha grammatik xatolar qiladi"
        })

    score = min(score, 100)
    risk_level = "XAVFSIZ" if score < 25 else "SHUBHALI" if score < 60 else "XAVFLI"
    risk_color = "green" if score < 25 else "yellow" if score < 60 else "red"

    if score < 25:
        recommendations = ["Email xavfsiz ko'rinadi", "Baribir noma'lum havolalarga bosmaslik tavsiya etiladi"]
    elif score < 60:
        recommendations = [
            "Bu emailga ehtiyotkorlik bilan yondashing",
            "Jo'natuvchi emailini rasmiy saytdan tekshiring",
            "Hech qanday ma'lumot bermang"
        ]
    else:
        recommendations = [
            "Bu email FISHING bo'lishi ehtimoli katta!",
            "Hech qanday havolaga bosmang",
            "Emailni spam/phishing sifatida belgilang",
            "IT xizmatingizga xabar bering"
        ]

    return {
        "score": score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "indicators": indicators,
        "recommendations": recommendations,
        "urls_found": urls,
        "analyzed_at": datetime.now().isoformat()
    }


def get_training_scenarios() -> List[Dict]:
    return [
        {
            "id": 1,
            "title": "Elektron pochta tekshiruvi",
            "category": "email",
            "difficulty": "oson",
            "scenario": """
Jo'natuvchi: security@paypa1-verify.tk
Mavzu: DARHOL! Hisobingiz bloklandi!

Hurmatli foydalanuvchi,

Sizning PayPal hisobingizda shubhali faoliyat aniqlandi. 
ZUDLIK BILAN quyidagi havolaga bosib hisobingizni tasdiqlang:

http://paypal-secure-verify.xyz/login?token=abc123

24 soat ichida tasdiqlasangiz, hisobingiz o'chiriladi.

PayPal Xavfsizlik Xizmati
            """,
            "question": "Bu email qanday tavsiflanadi?",
            "options": [
                "Haqiqiy PayPal xabari",
                "Fishing hujumi (Phishing Attack)",
                "Spam xabar",
                "Xato yuborilgan email"
            ],
            "correct": 1,
            "explanation": "Bu FISHING hujumi! Ko'rsatkichlar: 1) 'paypa1' - noto'g'ri yozilgan (1 vs l), 2) '.tk' shubhali domen, 3) 'DARHOL/ZUDLIK' - shoshilinch til, 4) HTTP (HTTPS emas), 5) Shubhali subdomen 'paypal-secure-verify.xyz'"
        },
        {
            "id": 2,
            "title": "URL xavfsizligi",
            "category": "url",
            "difficulty": "o'rta",
            "scenario": "Bankingiz SMS yubordi: 'Hisobingizni tasdiqlang: http://kapital-bank-verify.ml/secure/login'",
            "question": "Bu SMS haqiqiymi?",
            "options": [
                "Ha, bank rasmiy SMSi",
                "Shubhali, lekin xavfsiz bo'lishi mumkin",
                "Soxta - fishing urinishi",
                "Noma'lum"
            ],
            "correct": 2,
            "explanation": "Bu SOXTA SMS! Sabablari: 1) '.ml' - bepul va shubhali TLD, 2) Kapitalbank.uz rasmiy domeni emas, 3) Banklar hech qachon SMS orqali login so'ramaydi, 4) 'verify' so'zi fishing belgilaridan biri"
        },
        {
            "id": 3,
            "title": "Social Engineering",
            "category": "social",
            "difficulty": "qiyin",
            "scenario": "Telefon qo'ng'irog'i: 'Men Microsoft texnik yordamidanman. Kompyuteringizda virus aniqladik. Darhol remote access berishingiz kerak, aks holda 2 soatdan keyin ma'lumotlaringiz o'chiriladi!'",
            "question": "Nima qilasiz?",
            "options": [
                "Remote access beraman, ular yordam qiladi",
                "Isming va raqamingni so'rayman",
                "Qo'ng'irog'ni to'xtatib, Microsoft rasmiy raqamini topib chaqiraman",
                "IT bo'limga aytaman va hech narsa qilmayman"
            ],
            "correct": 3,
            "explanation": "D HA to'g'ri! Sabablari: 1) Microsoft hech qachon o'zi qo'ng'iroq qilmaydi, 2) Vaqt bosimi - social engineering taktikasi, 3) Hech qachon noma'lum odamlarga remote access bermang, 4) IT bo'limga xabar berish eng to'g'ri yo'l"
        },
        {
            "id": 4,
            "title": "Parol xavfsizligi",
            "category": "password",
            "difficulty": "oson",
            "scenario": "Do'stingiz sizdan: 'Parolim esimdan chiqdi, bitta hisobingga kirib menga o'sha parolni yuboring' deb so'radi.",
            "question": "Nima qilasiz?",
            "options": [
                "Parolimni yubordim, u ishonchli odam",
                "Parolimni bermayman, o'zi parolini tiklashi kerak",
                "Faqat bitta marta beraman",
                "Parolni SMS orqali yubordim"
            ],
            "correct": 1,
            "explanation": "B HA to'g'ri! Parolni HECH QACHON hech kimga bermang, hatto yaqin odamlarga ham. Sababi: 1) Hisob xavfsizligi buziladi, 2) Ular o'z hisoblariga kirishi kerak, 3) 'Ishonchli' degan gap parolni berish uchun asos emas"
        },
        {
            "id": 5,
            "title": "2FA muhimligi",
            "category": "2fa",
            "difficulty": "o'rta",
            "scenario": "Emailingizga: 'Sizning hisobingizga kirish urinishi Rossiyadan aniqlandi. Agar siz bo'lmasangiz, quyidagi kodni kiriting: 847291' degan xabar keldi.",
            "question": "Bu kodni kiritasizmi?",
            "options": [
                "Ha, hisobimni himoya qilish uchun",
                "Yo'q, bu 2FA kodini so'rash fishing bo'lishi mumkin",
                "Kodni do'stimga so'rayman",
                "Hisobni o'chiraman"
            ],
            "correct": 1,
            "explanation": "B HA to'g'ri! Bu 2FA bypass fishing! Hujumchi sizning 2FA kodingizni o'g'irlash uchun: 1) Asl saytga kiradi, 2) Sizga 'fishing email' yuboradi, 3) Siz kodni unga bersangiz - u kiradi. Hech qachon 2FA kodingizni email/SMS orqali so'ragan odamlarga bermang!"
        }
    ]
