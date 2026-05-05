#!/usr/bin/env python3
"""
CyberShieldPro - Fishing Simulatsiya Serveri
Python Flask backend
"""

from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from flask_cors import CORS
import json, os, datetime, uuid, hashlib, secrets
from pathlib import Path

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    return response

DATA_FILE = "data.json"

def load_data():
    if not os.path.exists(DATA_FILE):
        return {
            "employees": [
                {"id": "emp1", "name": "Alisher Karimov", "email": "alisher@company.uz", "department": "Buxgalteriya", "risk": 87, "phishing_sent": 0, "phishing_clicked": 0, "trained": False},
                {"id": "emp2", "name": "Dilnoza Yusupova", "email": "dilnoza@company.uz", "department": "IT", "risk": 54, "phishing_sent": 0, "phishing_clicked": 0, "trained": True},
                {"id": "emp3", "name": "Bobur Rahimov", "email": "bobur@company.uz", "department": "HR", "risk": 23, "phishing_sent": 0, "phishing_clicked": 0, "trained": True},
                {"id": "emp4", "name": "Malika Toshmatova", "email": "malika@company.uz", "department": "Sotish", "risk": 76, "phishing_sent": 0, "phishing_clicked": 0, "trained": False},
                {"id": "emp5", "name": "Sardor Umarov", "email": "sardor@company.uz", "department": "Marketing", "risk": 45, "phishing_sent": 0, "phishing_clicked": 0, "trained": False},
                {"id": "emp6", "name": "Nilufar Hasanova", "email": "nilufar@company.uz", "department": "Yuridik", "risk": 52, "phishing_sent": 0, "phishing_clicked": 0, "trained": False},
                {"id": "emp7", "name": "Jasur Mirzayev", "email": "jasur@company.uz", "department": "Logistika", "risk": 19, "phishing_sent": 0, "phishing_clicked": 0, "trained": True},
                {"id": "emp8", "name": "Feruza Qodirova", "email": "feruza@company.uz", "department": "Ombor", "risk": 71, "phishing_sent": 0, "phishing_clicked": 0, "trained": False},
                {"id": "emp9", "name": "Ibrohim Nazarov", "email": "ibrohim@company.uz", "department": "Xavfsizlik", "risk": 12, "phishing_sent": 0, "phishing_clicked": 0, "trained": True},
                {"id": "emp10", "name": "Zulfiya Ergasheva", "email": "zulfiya@company.uz", "department": "Qo'llab-quvvatlash", "risk": 48, "phishing_sent": 0, "phishing_clicked": 0, "trained": False},
            ],
            "simulations": [],
            "scan_results": [],
            "training_scores": []
        }
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# === AUTH ===
ADMIN_CREDENTIALS = {
    "admin": hashlib.sha256("admin123".encode()).hexdigest(),
    "superadmin": hashlib.sha256("cyber2024".encode()).hexdigest()
}

@app.route('/api/auth/login', methods=['POST'])
def login():
    body = request.json
    username = body.get('username', '')
    password = body.get('password', '')
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    if username in ADMIN_CREDENTIALS and ADMIN_CREDENTIALS[username] == pwd_hash:
        token = secrets.token_hex(32)
        return jsonify({"success": True, "token": token, "username": username, "message": "Muvaffaqiyatli kirish!"})
    return jsonify({"success": False, "message": "Login yoki parol noto'g'ri"}), 401

# === EMPLOYEES ===
@app.route('/api/employees', methods=['GET'])
def get_employees():
    data = load_data()
    return jsonify(data['employees'])

@app.route('/api/employees', methods=['POST'])
def add_employee():
    data = load_data()
    emp = request.json
    emp['id'] = 'emp' + str(uuid.uuid4())[:8]
    emp['phishing_sent'] = 0
    emp['phishing_clicked'] = 0
    emp['trained'] = False
    data['employees'].append(emp)
    save_data(data)
    return jsonify({"success": True, "employee": emp})

@app.route('/api/employees/<emp_id>', methods=['DELETE'])
def delete_employee(emp_id):
    data = load_data()
    data['employees'] = [e for e in data['employees'] if e['id'] != emp_id]
    save_data(data)
    return jsonify({"success": True})

# === PHISHING SIMULATION ===
@app.route('/api/simulation/send', methods=['POST'])
def send_simulation():
    body = request.json
    employee_ids = body.get('employee_ids', [])
    template = body.get('template', 'bank')
    
    data = load_data()
    sim_id = str(uuid.uuid4())[:12]
    
    sent_to = []
    for emp in data['employees']:
        if emp['id'] in employee_ids:
            emp['phishing_sent'] = emp.get('phishing_sent', 0) + 1
            sent_to.append({
                "id": emp['id'],
                "name": emp['name'],
                "email": emp['email'],
                "department": emp['department'],
                "tracking_url": f"http://localhost:8000/track/{sim_id}/{emp['id']}"
            })
    
    simulation = {
        "id": sim_id,
        "template": template,
        "sent_at": datetime.datetime.now().isoformat(),
        "sent_to": sent_to,
        "clicked": [],
        "click_count": 0,
        "status": "active"
    }
    
    data['simulations'].append(simulation)
    save_data(data)
    
    return jsonify({
        "success": True,
        "simulation_id": sim_id,
        "sent_count": len(sent_to),
        "sent_to": sent_to,
        "tracking_urls": [s['tracking_url'] for s in sent_to],
        "message": f"{len(sent_to)} ta xodimga fishing simulatsiyasi yuborildi"
    })

@app.route('/track/<sim_id>/<emp_id>')
def track_click(sim_id, emp_id):
    """Xodim fishing havolasini bosganda bu sahifa ochiladi"""
    data = load_data()
    
    emp_name = "Xodim"
    for emp in data['employees']:
        if emp['id'] == emp_id:
            emp['phishing_clicked'] = emp.get('phishing_clicked', 0) + 1
            emp['risk'] = min(100, emp.get('risk', 50) + 15)
            emp_name = emp['name']
            break
    
    for sim in data['simulations']:
        if sim['id'] == sim_id:
            if emp_id not in sim.get('clicked', []):
                sim.setdefault('clicked', []).append(emp_id)
                sim['click_count'] = sim.get('click_count', 0) + 1
                sim.setdefault('click_details', []).append({
                    "emp_id": emp_id,
                    "clicked_at": datetime.datetime.now().isoformat(),
                    "ip": request.remote_addr
                })
            break
    
    save_data(data)
    
    # Warning page
    return render_template_string('''
<!DOCTYPE html>
<html lang="uz">
<head>
<meta charset="UTF-8">
<title>⚠️ XAVFSIZLIK OGOHLANTIRISHI</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:#0a0e1a; color:white; font-family:'Courier New',monospace;
         display:flex; align-items:center; justify-content:center; min-height:100vh; }
  .box { background:#111827; border:2px solid #ef4444; border-radius:16px;
         padding:48px; max-width:560px; text-align:center; }
  .icon { font-size:64px; margin-bottom:24px; animation: shake 0.5s 3; }
  @keyframes shake { 0%,100%{transform:translateX(0)} 25%{transform:translateX(-8px)} 75%{transform:translateX(8px)} }
  h1 { color:#ef4444; font-size:22px; letter-spacing:2px; margin-bottom:12px; }
  .subtitle { color:#f87171; font-size:13px; margin-bottom:24px; letter-spacing:1px; }
  .info { background:#1f2937; border-radius:10px; padding:20px; margin-bottom:24px;
          text-align:left; font-size:13px; line-height:2; }
  .info span { color:#fbbf24; }
  .warn { color:#6b7280; font-size:11px; letter-spacing:1px; }
  .btn { display:inline-block; margin-top:20px; padding:12px 32px;
         background:linear-gradient(135deg,#7c3aed,#a855f7); border-radius:8px;
         color:white; text-decoration:none; font-size:12px; letter-spacing:2px; }
</style>
</head>
<body>
<div class="box">
  <div class="icon">🎣</div>
  <h1>FISHING HUJUMI ANIQLANDI!</h1>
  <div class="subtitle">// BU KORPORATIV XAVFSIZLIK TESTI EDI</div>
  <div class="info">
    <div>Xodim: <span>{{ name }}</span></div>
    <div>Sana: <span>{{ time }}</span></div>
    <div>Holat: <span style="color:#ef4444;">⚠ Havola bosildi</span></div>
    <div>Xavf darajasi: <span style="color:#ef4444;">OSHDI +15%</span></div>
  </div>
  <p class="warn">HAQIQIY FISHING HUJUMIDA SИЗНИНГ MA'LUMOTLARINGIZ O'G'IRLANAR EDI.</p>
  <p class="warn" style="margin-top:8px;">Noma'lum havolalarni HECH QACHON bosmang.</p>
  <a href="#" class="btn">TRENING BOSHLASH</a>
</div>
</body>
</html>
''', name=emp_name, time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route('/api/simulation/results', methods=['GET'])
def get_simulation_results():
    data = load_data()
    return jsonify(data.get('simulations', []))

@app.route('/api/simulation/<sim_id>', methods=['GET'])
def get_simulation(sim_id):
    data = load_data()
    for sim in data.get('simulations', []):
        if sim['id'] == sim_id:
            return jsonify(sim)
    return jsonify({"error": "Topilmadi"}), 404

# === PHISHING SCANNER ===
@app.route('/api/scan', methods=['POST'])
def scan_url():
    body = request.json
    target = body.get('url', '') or body.get('email', '')
    
    # Simulatsiya qilingan tahlil
    indicators = []
    risk_score = 0
    
    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'account', 'bank', 'paypal', 'password', 'click', 'urgent', 'free', 'win']
    suspicious_domains = ['bit.ly', 'tinyurl', 'goo.gl', '0.0.0.0', 'xyz', 'tk', 'ml', 'ga']
    
    target_lower = target.lower()
    
    for kw in suspicious_keywords:
        if kw in target_lower:
            indicators.append(f"Shubhali kalit so'z topildi: '{kw}'")
            risk_score += 12
    
    for domain in suspicious_domains:
        if domain in target_lower:
            indicators.append(f"Qisqartirilgan/shubhali domen: '{domain}'")
            risk_score += 25
    
    if '@' in target and target.count('@') > 1:
        indicators.append("Bir nechta @ belgisi — fishing belgisi")
        risk_score += 30
    
    if 'http://' in target_lower and 'https://' not in target_lower:
        indicators.append("Xavfli protokol: HTTP (HTTPS emas)")
        risk_score += 20
    
    if len([c for c in target if not c.isascii()]) > 0:
        indicators.append("Unicode/xorijiy belgilar aniqlandi")
        risk_score += 35
    
    if not indicators:
        indicators.append("Aniq xavfli belgilar topilmadi")
    
    risk_score = min(100, risk_score)
    
    if risk_score >= 70:
        verdict = "XAVFLI"
        color = "red"
    elif risk_score >= 40:
        verdict = "SHUBHALI"
        color = "yellow"
    else:
        verdict = "XAVFSIZ"
        color = "green"
    
    result = {
        "id": str(uuid.uuid4())[:8],
        "target": target,
        "risk_score": risk_score,
        "verdict": verdict,
        "color": color,
        "indicators": indicators,
        "scanned_at": datetime.datetime.now().isoformat(),
        "checks": {
            "ssl": "https://" in target_lower,
            "domain_age": "Noma'lum",
            "blacklist": risk_score > 50,
            "redirect": "bit.ly" in target_lower or "tinyurl" in target_lower
        }
    }
    
    data = load_data()
    data.setdefault('scan_results', []).insert(0, result)
    if len(data['scan_results']) > 50:
        data['scan_results'] = data['scan_results'][:50]
    save_data(data)
    
    return jsonify(result)

@app.route('/api/scan/history', methods=['GET'])
def scan_history():
    data = load_data()
    return jsonify(data.get('scan_results', [])[:20])

# === DASHBOARD STATS ===
@app.route('/api/stats', methods=['GET'])
def get_stats():
    data = load_data()
    employees = data.get('employees', [])
    simulations = data.get('simulations', [])
    scans = data.get('scan_results', [])
    
    total_sent = sum(e.get('phishing_sent', 0) for e in employees)
    total_clicked = sum(e.get('phishing_clicked', 0) for e in employees)
    avg_risk = round(sum(e.get('risk', 0) for e in employees) / max(len(employees), 1))
    
    dept_risks = {}
    for e in employees:
        dept = e.get('department', 'Boshqa')
        if dept not in dept_risks:
            dept_risks[dept] = []
        dept_risks[dept].append(e.get('risk', 0))
    
    dept_avg = {k: round(sum(v)/len(v)) for k, v in dept_risks.items()}
    
    return jsonify({
        "total_employees": len(employees),
        "total_simulations": len(simulations),
        "total_sent": total_sent,
        "total_clicked": total_clicked,
        "click_rate": round(total_clicked / max(total_sent, 1) * 100, 1),
        "avg_risk": avg_risk,
        "trained_count": sum(1 for e in employees if e.get('trained')),
        "total_scans": len(scans),
        "high_risk_employees": sorted([e for e in employees if e.get('risk', 0) >= 60], key=lambda x: -x['risk'])[:5],
        "department_risks": dept_avg,
        "recent_simulations": simulations[-5:] if simulations else []
    })

# === TRAINING ===
@app.route('/api/training/complete', methods=['POST'])
def complete_training():
    body = request.json
    emp_id = body.get('emp_id')
    score = body.get('score', 0)
    
    data = load_data()
    for emp in data['employees']:
        if emp['id'] == emp_id:
            emp['trained'] = True
            emp['risk'] = max(5, emp.get('risk', 50) - 20)
            break
    
    data.setdefault('training_scores', []).append({
        "emp_id": emp_id,
        "score": score,
        "date": datetime.datetime.now().isoformat()
    })
    save_data(data)
    return jsonify({"success": True, "message": "Trening yakunlandi, xavf darajasi kamaydi"})

# Main HTML page
@app.route('/')
def index():
    return open('index.html', encoding='utf-8').read()

if __name__ == '__main__':
    print("🛡️  CyberShieldPro serveri ishga tushmoqda...")
    print("📡  http://localhost:8000")
    print("🔑  Admin: admin / admin123")
    app.run(host='0.0.0.0', port=8000, debug=True)
