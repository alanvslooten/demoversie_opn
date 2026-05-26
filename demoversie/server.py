#!/usr/bin/env python3
"""KinderKompas v2 — volledig backend met wachtlijst, rondleidingen, contacten, weekbeschikbaarheid"""
import sqlite3, os, json, hashlib, hmac, base64, time, io, csv
from datetime import datetime, timedelta, date
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, Response

app = Flask(__name__, static_url_path='')
SECRET   = os.environ.get('JWT_SECRET', 'kk-v2-secret-2026-zX7nQ')
DB_PATH  = os.path.join(os.path.dirname(__file__), 'kinderkompas.db')
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ── CORS ──
@app.after_request
def cors(r):
    r.headers['Access-Control-Allow-Origin']  = '*'
    r.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    r.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,PATCH,OPTIONS'
    return r

# ── STATIC SERVING ──
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path.startswith('api/'): return jsonify({'error':'Not found'}), 404
    sd = os.path.join(os.path.dirname(__file__), 'static')
    if path and os.path.isfile(os.path.join(sd, path)):
        return send_from_directory(sd, path)
    idx = os.path.join(sd, 'index.html')
    return send_from_directory(sd, 'index.html') if os.path.exists(idx) else ('index.html niet gevonden', 404)

# ── JWT ──
def b64e(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()
def b64d(s):
    p = 4 - len(s) % 4
    if p != 4: s += '=' * p
    return base64.urlsafe_b64decode(s)
def make_token(payload):
    h = b64e(json.dumps({'alg':'HS256','typ':'JWT'}))
    payload['exp'] = time.time() + 86400 * 7
    b = b64e(json.dumps(payload))
    sig = hmac.new(SECRET.encode(), f'{h}.{b}'.encode(), 'sha256').digest()
    return f'{h}.{b}.{b64e(sig)}'
def verify_token(tok):
    try:
        h, b, sig = tok.split('.')
        exp = hmac.new(SECRET.encode(), f'{h}.{b}'.encode(), 'sha256').digest()
        if not hmac.compare_digest(b64d(sig), exp): return None
        p = json.loads(b64d(b))
        return None if p.get('exp', 0) < time.time() else p
    except: return None

def require_auth(f):
    @wraps(f)
    def w(*a, **kw):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '): return jsonify({'error':'Unauthorized'}), 401
        p = verify_token(auth[7:])
        if not p: return jsonify({'error':'Invalid token'}), 401
        request.user = p; return f(*a, **kw)
    return w
def require_admin(f):
    @wraps(f)
    def w(*a, **kw):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '): return jsonify({'error':'Unauthorized'}), 401
        p = verify_token(auth[7:])
        if not p: return jsonify({'error':'Invalid token'}), 401
        if p.get('role') != 'admin': return jsonify({'error':'Admin required'}), 403
        request.user = p; return f(*a, **kw)
    return w

# ── DB ──
def get_db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys = ON')
    return c
def q2d(row): return dict(row) if row else None
def rows2d(rows):
    result = []
    for r in rows:
        d = dict(r)
        for k,v in d.items():
            if isinstance(v, str):
                try: d[k] = json.loads(v)
                except: pass
        result.append(d)
    return result

def log_action(uid, action, details=''):
    c = get_db(); c.execute('INSERT INTO activity_log(user_id,action,details)VALUES(?,?,?)',(uid,action,details)); c.commit(); c.close()

def calc_obs_status(child_id, conn):
    row = conn.execute('SELECT obs_date,next_due FROM observations WHERE child_id=? ORDER BY obs_date DESC LIMIT 1',(child_id,)).fetchone()
    if not row: return 'overdue', None, None
    nd = row['next_due']
    if not nd: return 'done', row['obs_date'], None
    due = datetime.strptime(nd,'%Y-%m-%d').date()
    diff = (due - date.today()).days
    if diff < 0:   return 'overdue', row['obs_date'], nd
    if diff <= 30: return 'needed',  row['obs_date'], nd
    return 'done', row['obs_date'], nd

def score_waitlist_child(wl, conn):
    """Priority scoring for waitlist placement"""
    score = 0
    today = date.today()
    # Internal = sibling already placed
    if wl['list_type'] == 'intern': score += 100
    # Desired start date proximity
    if wl['desired_start']:
        ds = datetime.strptime(wl['desired_start'], '%Y-%m-%d').date()
        days_until = (ds - today).days
        if 0 <= days_until <= 30: score += 50
        elif 31 <= days_until <= 90: score += 25
    # Day combo rendability (Mon/Tue/Thu = high demand)
    days = json.loads(wl['days']) if isinstance(wl['days'], str) else wl['days']
    high_demand = [0, 1, 3]  # Ma, Di, Do
    score += sum(15 for i,d in enumerate(days) if d and i in high_demand)
    score += sum(10 for i,d in enumerate(days) if d and i not in high_demand)
    # FIFO tiebreaker — earlier = higher score (max 20 pts)
    if wl['created_at']:
        try:
            created = datetime.strptime(wl['created_at'][:10], '%Y-%m-%d').date()
            days_on_list = (today - created).days
            fifo_score = max(0, 20 - (days_on_list // 30))
            score += fifo_score
        except: pass
    return score

# ── SCHEMA + SEED ──
def init_db():
    c = get_db(); cur = c.cursor()
    cur.executescript('''
    CREATE TABLE IF NOT EXISTS db_meta(key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'staff', initials TEXT, color TEXT DEFAULT '#6366f1',
        contract_hours INTEGER DEFAULT 32, vacation_hours_total INTEGER DEFAULT 160,
        vacation_hours_used INTEGER DEFAULT 0, worked_hours_month INTEGER DEFAULT 0,
        active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS children(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, dob TEXT NOT NULL, group_name TEXT NOT NULL,
        group_color TEXT DEFAULT '#6366f1', assigned_leidster_id INTEGER REFERENCES users(id),
        days TEXT DEFAULT '[0,0,0,0,0]', contact_name TEXT, contact_phone TEXT, notes TEXT,
        active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS observations(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        child_id INTEGER NOT NULL REFERENCES children(id),
        leidster_id INTEGER REFERENCES users(id),
        obs_date TEXT NOT NULL, next_due TEXT, notes TEXT, completed INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS observation_files(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        observation_id INTEGER NOT NULL REFERENCES observations(id),
        filename TEXT NOT NULL, original_name TEXT NOT NULL,
        file_type TEXT, file_size INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS shifts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        shift_date TEXT NOT NULL, shift_type TEXT DEFAULT 'werk',
        start_time TEXT, end_time TEXT, notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS leave_requests(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        leave_type TEXT DEFAULT 'vakantie',
        from_date TEXT NOT NULL, to_date TEXT NOT NULL, days INTEGER DEFAULT 1,
        status TEXT DEFAULT 'pending', notes TEXT,
        reviewed_by INTEGER REFERENCES users(id), reviewed_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS weekly_availability(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        week_number INTEGER NOT NULL, year INTEGER NOT NULL,
        day_of_week INTEGER NOT NULL, session TEXT NOT NULL,
        UNIQUE(user_id, week_number, year, day_of_week, session));
    CREATE TABLE IF NOT EXISTS waitlist(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        list_type TEXT DEFAULT 'extern',
        parent_name TEXT NOT NULL, parent2_name TEXT,
        email TEXT NOT NULL, phone TEXT,
        address TEXT, bsn_parent TEXT, iban TEXT,
        child_name TEXT NOT NULL, child_dob TEXT, bsn_child TEXT,
        desired_start TEXT, days TEXT DEFAULT '[0,0,0,0,0]',
        contract_type TEXT DEFAULT '52weken', opvang_type TEXT DEFAULT 'KDV',
        status TEXT DEFAULT 'wachtend',
        proposal_deadline TEXT, proposal_sent_at TEXT,
        priority_score INTEGER DEFAULT 0, notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS contacts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, email TEXT, phone TEXT,
        status TEXT DEFAULT 'niet_ingeschreven',
        waitlist_id INTEGER REFERENCES waitlist(id),
        notes TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS tours(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        contact_id INTEGER REFERENCES contacts(id),
        tour_date TEXT NOT NULL, tour_time TEXT NOT NULL,
        guide_id INTEGER REFERENCES users(id),
        attendees INTEGER DEFAULT 1,
        status TEXT DEFAULT 'gepland',
        notes TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS activity_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id),
        action TEXT NOT NULL, details TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    ''')

    if cur.execute("SELECT value FROM db_meta WHERE key='seeded_v2'").fetchone():
        c.close(); print('✓ Database ready'); return

    def hp(pw): return hashlib.sha256(f'{pw}{SECRET}'.encode()).hexdigest()
    today = date.today()
    def rdate(days): return (today + timedelta(days=days)).isoformat()

    # Users
    for u in [
        ('Beheerder','beheerder@kdv.nl',hp('admin123'),'admin','BH','#6366f1',40,200,0,0),
        ('Lisa de Bruin','lisa@kdv.nl',hp('leidster1'),'staff','LB','#8b5cf6',32,160,24,88),
        ('Sarah Jansen','sarah@kdv.nl',hp('leidster2'),'staff','SJ','#1d9bf0',28,140,16,74),
        ('Mieke van Dijk','mieke@kdv.nl',hp('leidster3'),'staff','MV','#f472b6',36,180,40,96),
        ('Tom Hartman','tom@kdv.nl',hp('stagair1'),'staff','TH','#4ade80',16,0,0,42),
    ]:
        cur.execute('INSERT OR IGNORE INTO users(name,email,password_hash,role,initials,color,contract_hours,vacation_hours_total,vacation_hours_used,worked_hours_month)VALUES(?,?,?,?,?,?,?,?,?,?)',u)

    lid=cur.execute("SELECT id FROM users WHERE email='lisa@kdv.nl'").fetchone()[0]
    sid=cur.execute("SELECT id FROM users WHERE email='sarah@kdv.nl'").fetchone()[0]
    mid=cur.execute("SELECT id FROM users WHERE email='mieke@kdv.nl'").fetchone()[0]
    tid=cur.execute("SELECT id FROM users WHERE email='tom@kdv.nl'").fetchone()[0]

    # Children
    def dob(m): return (today - timedelta(days=int(m*30.4))).isoformat()
    kids = [
        ('Emma de Jong',dob(14),'Babygroep','#22c55e',lid,'[1,0,1,0,1]','Maria de Jong','06-12345678'),
        ('Liam Bakker',dob(32),'Dreumesgroep','#8b5cf6',sid,'[1,1,0,1,0]','Jan Bakker','06-23456789'),
        ('Sophie van den Berg',dob(40),'Dreumesgroep','#8b5cf6',lid,'[0,1,1,1,0]','Karin v.d. Berg','06-34567890'),
        ('Noah Smit',dob(42),'Peutergroep','#1d9bf0',mid,'[1,0,0,1,1]','Peter Smit','06-45678901'),
        ('Olivia Visser',dob(47),'Peutergroep','#1d9bf0',sid,'[1,1,1,0,0]','Anne Visser','06-56789012'),
        ('Lucas de Boer',dob(16),'Babygroep','#22c55e',mid,'[0,1,0,1,1]','Rob de Boer','06-67890123'),
        ('Mia Janssen',dob(25),'Dreumesgroep','#8b5cf6',lid,'[1,0,1,0,1]','Els Janssen','06-78901234'),
        ('Finn de Wit',dob(43),'Peutergroep','#1d9bf0',mid,'[0,0,1,1,1]','Mark de Wit','06-89012345'),
        ('Zoë Mulder',dob(11),'Babygroep','#22c55e',sid,'[1,1,0,0,0]','Linda Mulder','06-90123456'),
        ('Lars Hendriks',dob(39),'Dreumesgroep','#8b5cf6',lid,'[1,0,0,1,1]','Daan Hendriks','06-01234567'),
        ('Noor Pietersen',dob(41),'Peutergroep','#1d9bf0',mid,'[0,1,1,0,1]','Lies Pietersen','06-11223344'),
        ('Sam de Graaf',dob(13),'Babygroep','#22c55e',sid,'[1,1,1,0,0]','Tom de Graaf','06-22334455'),
    ]
    for ch in kids:
        cur.execute('INSERT INTO children(name,dob,group_name,group_color,assigned_leidster_id,days,contact_name,contact_phone)VALUES(?,?,?,?,?,?,?,?)',ch)

    def cid(name): return cur.execute('SELECT id FROM children WHERE name=?',(name,)).fetchone()[0]
    eid=cid('Emma de Jong'); bid=cid('Liam Bakker'); nid=cid('Noah Smit')
    oid=cid('Olivia Visser'); mid2=cid('Mia Janssen'); fid=cid('Finn de Wit')

    obs_notes='Ontwikkeling verloopt goed. Motoriek en taalontwikkeling worden nauwkeurig gevolgd. Kind toont positieve sociale interactie met leidsters en groepsgenoten. Specifieke observatiemomenten bevestigen leeftijdsadequate ontwikkeling op alle domeinen.'
    for child_id,leid_id,od,nd in [
        (eid,lid,rdate(-60),rdate(123)),(bid,sid,rdate(-200),rdate(-17)),
        (nid,mid,rdate(-90),rdate(93)),(oid,sid,rdate(-150),rdate(33)),
        (mid2,lid,rdate(-210),rdate(-27)),(fid,mid,rdate(-45),rdate(138)),
    ]:
        cur.execute('INSERT INTO observations(child_id,leidster_id,obs_date,next_due,notes,completed)VALUES(?,?,?,?,?,1)',(child_id,leid_id,od,nd,obs_notes))

    # Shifts current week
    monday = today - timedelta(days=today.weekday())
    for uid,day,st,et in [
        (lid,0,'07:30','16:00'),(lid,1,'07:30','16:00'),(lid,3,'07:30','14:00'),(lid,4,'07:30','16:00'),
        (sid,0,'09:00','18:30'),(sid,2,'09:00','18:30'),(sid,3,'09:00','18:30'),
        (mid,1,'08:00','17:00'),(mid,2,'08:00','17:00'),(mid,4,'08:00','17:00'),
        (tid,0,'09:00','13:00'),(tid,2,'09:00','13:00'),
    ]:
        cur.execute('INSERT INTO shifts(user_id,shift_date,shift_type,start_time,end_time)VALUES(?,?,?,?,?)',
                    (uid,(monday+timedelta(days=day)).isoformat(),'werk',st,et))

    # Leave requests
    cur.execute('INSERT INTO leave_requests(user_id,leave_type,from_date,to_date,days,notes)VALUES(?,?,?,?,?,?)',
                (sid,'vakantie',rdate(25),rdate(29),3,'Zomervakantie'))
    cur.execute('INSERT INTO leave_requests(user_id,leave_type,from_date,to_date,days,notes)VALUES(?,?,?,?,?,?)',
                (lid,'verlof',rdate(60),rdate(60),1,'Arts afspraak'))

    # Weekly availability (weeks 23-40 current year)
    yr = today.year
    avail = [
        (lid,0,'ochtend'),(lid,0,'middag'),(lid,1,'ochtend'),(lid,3,'ochtend'),(lid,3,'middag'),(lid,4,'ochtend'),(lid,4,'middag'),
        (sid,0,'middag'),(sid,1,'ochtend'),(sid,1,'middag'),(sid,2,'middag'),(sid,3,'ochtend'),
        (mid,1,'ochtend'),(mid,1,'middag'),(mid,2,'ochtend'),(mid,2,'middag'),(mid,4,'ochtend'),(mid,4,'middag'),
    ]
    for wk in range(23, 41):
        for uid,dow,sess in avail:
            cur.execute('INSERT OR IGNORE INTO weekly_availability(user_id,week_number,year,day_of_week,session)VALUES(?,?,?,?,?)',(uid,wk,yr,dow,sess))

    # Waitlist
    wl_data = [
        ('extern','Petra van Dam',None,'petra@email.nl','06-11111111','Dorpstraat 5, Roosendaal',None,None,'Roos van Dam',rdate(-365+60),'2025-09-01','[1,1,0,1,0]','52weken','KDV','wachtend',None,85,'Voorkeur ochtendgroep'),
        ('intern','Familie Bakker','J. Bakker','jan.bakker@mail.nl','06-22222222','Kerkweg 12, Roosendaal',None,None,'Floor Bakker',rdate(-365+90),'2025-08-01','[1,0,1,0,1]','52weken','KDV','wachtend',None,130,'Broer Liam al geplaatst'),
        ('extern','Anne de Vries',None,'anne.devries@work.nl','06-33333333','Lindelaan 3, Etten-Leur',None,None,'Sem de Vries',rdate(-365+180),'2026-01-01','[0,1,1,1,0]','40weken','KDV','wachtend',None,60,'Woensdagmiddag niet nodig'),
        ('extern','M. Claassen',None,'m.claassen@mail.nl','06-44444444','Molenweg 8, Roosendaal',None,None,'Julie Claassen',rdate(-365+30),'2025-10-01','[1,1,1,0,0]','52weken','KDV','voorstel_verstuurd',rdate(7),95,'Voorstel verstuurd, wacht op reactie'),
        ('intern','Hendriks-Smit','D. Hendriks','d.hendriks@mail.nl','06-55555555','Bosweg 22, Roosendaal',None,None,'Tim Hendriks',rdate(-365+120),'2025-11-01','[1,0,1,1,0]','52weken','KDV','wachtend',None,110,'Zus Lars al geplaatst'),
        ('extern','L. Pietersen',None,'l.pietersen@gmail.com','06-66666666','Haverstraat 1, Roosendaal',None,None,'Bo Pietersen',rdate(-365+200),'2026-03-01','[0,1,0,1,1]','52weken','BSO','wachtend',None,45,'BSO aanvraag na school'),
    ]
    for w in wl_data:
        wid = cur.execute('INSERT INTO waitlist(list_type,parent_name,parent2_name,email,phone,address,bsn_parent,iban,child_name,child_dob,bsn_child,desired_start,days,contract_type,opvang_type,status,proposal_deadline,priority_score,notes)VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (w[0],w[1],w[2],w[3],w[4],w[5],w[6],w[7],w[8],w[9],None,w[10],json.dumps(json.loads(w[11]) if isinstance(w[11],str) else w[11]),w[12],w[13],w[14],w[15],w[16],w[17])).lastrowid

    # Contacts
    contacts = [
        ('Petra van Dam','petra@email.nl','06-11111111','wachtlijst',1,'Rondleiding gehad op 12 april'),
        ('Familie Bakker','jan.bakker@mail.nl','06-22222222','wachtlijst',2,'Intern — broer al geplaatst'),
        ('Anna Willems','anna.willems@mail.nl','06-77777777','niet_ingeschreven',None,'Rondleiding 3 mei, nog geen aanmelding'),
        ('Dhr. de Groot','degroot@mail.nl','06-88888888','niet_ingeschreven',None,'Interesse getoond via website'),
        ('M. Claassen','m.claassen@mail.nl','06-44444444','wachtlijst',4,'Plaatsingsvoorstel verstuurd'),
    ]
    for co in contacts:
        coid = cur.execute('INSERT INTO contacts(name,email,phone,status,waitlist_id,notes)VALUES(?,?,?,?,?,?)',co).lastrowid

    # Tours
    guide_id = lid
    for td,tt,ct,att,st,nt in [
        (rdate(-14),'10:00',1,2,'geweest','Stel had veel vragen over BKR'),
        (rdate(-7),'14:00',2,2,'geweest','Positieve indruk, interesse in maandag/woensdag'),
        (rdate(3),'10:30',3,1,'gepland','Eerste rondleiding voor nieuwe interesse'),
        (rdate(7),'15:00',4,2,'gepland','Twee ouders verwacht'),
        (rdate(-21),'11:00',5,1,'no-show','Niet verschenen, contact opnemen'),
    ]:
        cur.execute('INSERT INTO tours(contact_id,tour_date,tour_time,guide_id,attendees,status,notes)VALUES(?,?,?,?,?,?,?)',(ct,td,tt,guide_id,att,st,nt))

    # Activity log
    for uid,action,details in [
        (lid,'Observatie afgerond','Emma de Jong'),
        (sid,'Verlofaanvraag ingediend','3 vakantiedagen aangevraagd'),
        (None,'Wachtlijstaanmelding','Roos van Dam toegevoegd aan externe wachtlijst'),
        (None,'Plaatsingsvoorstel verstuurd','Julie Claassen — deadline '+rdate(7)),
        (mid,'Rondleiding ingepland','Familie Willems — '+rdate(3)),
    ]:
        cur.execute('INSERT INTO activity_log(user_id,action,details)VALUES(?,?,?)',(uid,action,details))

    cur.execute("INSERT INTO db_meta(key,value)VALUES('seeded_v2','1')")
    c.commit(); c.close(); print('✓ Database initialized with seed data v2')

# ══════════════════════════════
# AUTH
# ══════════════════════════════
@app.route('/api/auth/login', methods=['POST','OPTIONS'])
def login():
    if request.method=='OPTIONS': return jsonify({}),200
    d = request.get_json()
    email = (d.get('email') or '').lower().strip()
    ph = hashlib.sha256(f'{d.get("password","")}{SECRET}'.encode()).hexdigest()
    c = get_db()
    u = c.execute('SELECT * FROM users WHERE email=? AND password_hash=? AND active=1',(email,ph)).fetchone()
    c.close()
    if not u: return jsonify({'error':'Ongeldige inloggegevens'}),401
    u = dict(u)
    tok = make_token({'id':u['id'],'email':u['email'],'role':u['role'],'name':u['name']})
    return jsonify({'token':tok,'user':{'id':u['id'],'name':u['name'],'email':u['email'],'role':u['role'],'initials':u['initials'],'color':u['color']}})

@app.route('/api/auth/me')
@require_auth
def me():
    c=get_db(); u=c.execute('SELECT * FROM users WHERE id=?',(request.user['id'],)).fetchone(); c.close()
    if not u: return jsonify({'error':'Not found'}),404
    d=dict(u); d.pop('password_hash',None); return jsonify(d)

# ══════════════════════════════
# SEARCH
# ══════════════════════════════
@app.route('/api/search')
@require_auth
def search():
    q = (request.args.get('q') or '').strip().lower()
    if len(q) < 2: return jsonify({'children':[],'staff':[],'waitlist':[],'contacts':[]})
    c = get_db(); uid = request.user['id']; role = request.user['role']
    like = f'%{q}%'
    if role == 'admin':
        kids = c.execute('SELECT id,name,group_name,group_color,assigned_leidster_id FROM children WHERE active=1 AND LOWER(name) LIKE ? LIMIT 5',(like,)).fetchall()
    else:
        kids = c.execute('SELECT id,name,group_name,group_color,assigned_leidster_id FROM children WHERE active=1 AND assigned_leidster_id=? AND LOWER(name) LIKE ? LIMIT 5',(uid,like)).fetchall()
    staff = c.execute('SELECT id,name,role,initials,color FROM users WHERE active=1 AND LOWER(name) LIKE ? LIMIT 5',(like,)) .fetchall() if role=='admin' else []
    wl = c.execute('SELECT id,child_name,parent_name,status,list_type FROM waitlist WHERE LOWER(child_name) LIKE ? OR LOWER(parent_name) LIKE ? LIMIT 5',(like,like)).fetchall() if role=='admin' else []
    contacts = c.execute('SELECT id,name,email,phone,status FROM contacts WHERE LOWER(name) LIKE ? OR LOWER(email) LIKE ? LIMIT 5',(like,like)).fetchall() if role=='admin' else []
    c.close()
    return jsonify({'children':[dict(r) for r in kids],'staff':[dict(r) for r in staff],'waitlist':[dict(r) for r in wl],'contacts':[dict(r) for r in contacts]})

# ══════════════════════════════
# DASHBOARD
# ══════════════════════════════
@app.route('/api/dashboard')
@require_auth
def dashboard():
    c=get_db(); today=date.today().isoformat(); dow=date.today().weekday()
    total_children = c.execute('SELECT COUNT(*) FROM children WHERE active=1').fetchone()[0]
    ch_rows = c.execute('SELECT days FROM children WHERE active=1').fetchall()
    today_children = sum(1 for r in ch_rows if json.loads(r['days'])[dow])
    staff_today = c.execute('SELECT COUNT(*) FROM shifts WHERE shift_date=? AND shift_type="werk"',(today,)).fetchone()[0]
    pending_leave = c.execute('SELECT COUNT(*) FROM leave_requests WHERE status="pending"').fetchone()[0]
    wl_total = c.execute('SELECT COUNT(*) FROM waitlist WHERE status NOT IN ("geplaatst","afgewezen")').fetchone()[0]
    wl_proposals = c.execute('SELECT COUNT(*) FROM waitlist WHERE status="voorstel_verstuurd"').fetchone()[0]
    children = c.execute('SELECT id FROM children WHERE active=1').fetchall()
    obs_needed=obs_overdue=obs_done=0
    for ch in children:
        s,_,_ = calc_obs_status(ch['id'],c)
        if s=='overdue': obs_overdue+=1
        elif s=='needed': obs_needed+=1
        else: obs_done+=1
    tours_upcoming = c.execute("SELECT COUNT(*) FROM tours WHERE tour_date>=? AND status='gepland'",(today,)).fetchone()[0]
    activities = c.execute('SELECT al.*,u.name as user_name,u.color FROM activity_log al LEFT JOIN users u ON al.user_id=u.id ORDER BY al.created_at DESC LIMIT 8').fetchall()
    c.close()
    return jsonify({'total_children':total_children,'today_children':today_children,'staff_today':staff_today,'pending_leave':pending_leave,'wl_total':wl_total,'wl_proposals':wl_proposals,'obs_needed':obs_needed,'obs_overdue':obs_overdue,'obs_done':obs_done,'tours_upcoming':tours_upcoming,'activities':[dict(a) for a in activities]})

# ══════════════════════════════
# CHILDREN
# ══════════════════════════════
@app.route('/api/children', methods=['GET'])
@require_auth
def get_children():
    c=get_db(); uid=request.user['id']; role=request.user['role']
    if role=='admin':
        rows=c.execute('SELECT ch.*,u.name as leidster_name,u.color as leidster_color,u.initials as leidster_initials FROM children ch LEFT JOIN users u ON ch.assigned_leidster_id=u.id WHERE ch.active=1 ORDER BY ch.group_name,ch.name').fetchall()
    else:
        rows=c.execute('SELECT ch.*,u.name as leidster_name,u.color as leidster_color,u.initials as leidster_initials FROM children ch LEFT JOIN users u ON ch.assigned_leidster_id=u.id WHERE ch.active=1 AND ch.assigned_leidster_id=? ORDER BY ch.name',(uid,)).fetchall()
    result=[]
    for r in rows:
        d=dict(r)
        try: d['days']=json.loads(d['days'])
        except: pass
        d['obs_status'],d['last_obs'],d['next_obs_due']=calc_obs_status(d['id'],c)
        result.append(d)
    c.close(); return jsonify(result)

@app.route('/api/children', methods=['POST'])
@require_auth
def add_child():
    d=request.get_json(); c=get_db()
    cur=c.execute('INSERT INTO children(name,dob,group_name,group_color,assigned_leidster_id,days,contact_name,contact_phone,notes)VALUES(?,?,?,?,?,?,?,?,?)',
        (d['name'],d['dob'],d['group_name'],d.get('group_color','#6366f1'),d.get('assigned_leidster_id'),json.dumps(d.get('days',[0,0,0,0,0])),d.get('contact_name'),d.get('contact_phone'),d.get('notes')))
    cid=cur.lastrowid; c.commit(); c.close()
    log_action(request.user['id'],'Kind toegevoegd',d['name']); return jsonify({'id':cid}),201

@app.route('/api/children/<int:cid>', methods=['GET'])
@require_auth
def get_child(cid):
    c=get_db(); r=c.execute('SELECT ch.*,u.name as leidster_name FROM children ch LEFT JOIN users u ON ch.assigned_leidster_id=u.id WHERE ch.id=?',(cid,)).fetchone()
    if not r: return jsonify({'error':'Not found'}),404
    d=dict(r)
    try: d['days']=json.loads(d['days'])
    except: pass
    d['obs_status'],d['last_obs'],d['next_obs_due']=calc_obs_status(cid,c)
    obs=c.execute('SELECT o.*,u.name as leidster_name FROM observations o LEFT JOIN users u ON o.leidster_id=u.id WHERE o.child_id=? ORDER BY o.obs_date DESC',(cid,)).fetchall()
    d['observations']=[dict(o) for o in obs]; c.close(); return jsonify(d)

@app.route('/api/children/<int:cid>/assign', methods=['PATCH'])
@require_admin
def assign_child(cid):
    d=request.get_json(); c=get_db()
    c.execute('UPDATE children SET assigned_leidster_id=? WHERE id=?',(d.get('leidster_id'),cid))
    c.commit(); c.close(); log_action(request.user['id'],'Kind toegewezen',''); return jsonify({'message':'OK'})

# ══════════════════════════════
# OBSERVATIONS
# ══════════════════════════════
@app.route('/api/observations/overview')
@require_auth
def obs_overview():
    c=get_db(); uid=request.user['id']; role=request.user['role']
    if role=='admin':
        kids=c.execute('SELECT ch.*,u.name as leidster_name,u.initials as leidster_initials,u.color as leidster_color FROM children ch LEFT JOIN users u ON ch.assigned_leidster_id=u.id WHERE ch.active=1 ORDER BY ch.name').fetchall()
    else:
        kids=c.execute('SELECT ch.*,u.name as leidster_name,u.initials as leidster_initials,u.color as leidster_color FROM children ch LEFT JOIN users u ON ch.assigned_leidster_id=u.id WHERE ch.active=1 AND ch.assigned_leidster_id=? ORDER BY ch.name',(uid,)).fetchall()
    result=[]
    for ch in kids:
        d=dict(ch)
        try: d['days']=json.loads(d['days'])
        except: pass
        d['obs_status'],d['last_obs'],d['next_obs_due']=calc_obs_status(d['id'],c)
        obs=c.execute('SELECT o.*,u.name as ln FROM observations o LEFT JOIN users u ON o.leidster_id=u.id WHERE o.child_id=? ORDER BY o.obs_date DESC',(d['id'],)).fetchall()
        d['all_observations']=[dict(o) for o in obs]; result.append(d)
    c.close(); return jsonify(result)

@app.route('/api/observations', methods=['GET'])
@require_auth
def get_observations():
    c=get_db(); uid=request.user['id']; role=request.user['role']
    if role=='admin':
        rows=c.execute('SELECT o.*,ch.name as child_name,ch.group_name,u.name as leidster_name FROM observations o JOIN children ch ON o.child_id=ch.id LEFT JOIN users u ON o.leidster_id=u.id ORDER BY o.obs_date DESC').fetchall()
    else:
        rows=c.execute('SELECT o.*,ch.name as child_name,ch.group_name,u.name as leidster_name FROM observations o JOIN children ch ON o.child_id=ch.id LEFT JOIN users u ON o.leidster_id=u.id WHERE ch.assigned_leidster_id=? ORDER BY o.obs_date DESC',(uid,)).fetchall()
    c.close(); return jsonify([dict(r) for r in rows])

@app.route('/api/observations', methods=['POST'])
@require_auth
def add_observation():
    d=request.get_json(); od=d.get('obs_date',date.today().isoformat())
    nd=(datetime.strptime(od,'%Y-%m-%d')+timedelta(days=183)).strftime('%Y-%m-%d')
    c=get_db(); cur=c.execute('INSERT INTO observations(child_id,leidster_id,obs_date,next_due,notes,completed)VALUES(?,?,?,?,?,1)',
        (d['child_id'],request.user['id'],od,nd,d.get('notes','')))
    oid=cur.lastrowid; c.commit()
    ch=c.execute('SELECT name FROM children WHERE id=?',(d['child_id'],)).fetchone()
    c.close(); log_action(request.user['id'],'Observatie toegevoegd',ch['name'] if ch else '')
    return jsonify({'id':oid,'next_due':nd}),201

@app.route('/api/observations/export')
@require_auth
def export_observations():
    c=get_db(); uid=request.user['id']; role=request.user['role']
    if role=='admin':
        rows=c.execute('SELECT o.*,ch.name as child_name,ch.group_name,u.name as leidster_name FROM observations o JOIN children ch ON o.child_id=ch.id LEFT JOIN users u ON o.leidster_id=u.id ORDER BY ch.name,o.obs_date DESC').fetchall()
    else:
        rows=c.execute('SELECT o.*,ch.name as child_name,ch.group_name,u.name as leidster_name FROM observations o JOIN children ch ON o.child_id=ch.id LEFT JOIN users u ON o.leidster_id=u.id WHERE ch.assigned_leidster_id=? ORDER BY ch.name,o.obs_date DESC',(uid,)).fetchall()
    c.close()
    output=io.StringIO()
    w=csv.writer(output)
    w.writerow(['Kind','Groep','Datum','Volgende observatie','Leidster','Notities'])
    for r in rows:
        w.writerow([r['child_name'],r['group_name'],r['obs_date'],r['next_due'] or '',r['leidster_name'] or '',r['notes'] or ''])
    output.seek(0)
    return Response(output,mimetype='text/csv',headers={'Content-Disposition':'attachment;filename=observaties.csv'})

@app.route('/api/observations/<int:oid>/upload', methods=['POST'])
@require_auth
def upload_obs_file(oid):
    import uuid
    if 'file' not in request.files: return jsonify({'error':'No file'}),400
    f=request.files['file']
    ext=os.path.splitext(f.filename)[1].lower()
    if ext not in {'.jpg','.jpeg','.png','.heic','.heif','.pdf','.docx'}: return jsonify({'error':'Bestandstype niet toegestaan'}),400
    fn=f'{uuid.uuid4().hex}{ext}'; fp=os.path.join(UPLOAD_DIR,fn); f.save(fp)
    c=get_db(); cur=c.execute('INSERT INTO observation_files(observation_id,filename,original_name,file_type,file_size)VALUES(?,?,?,?,?)',(oid,fn,f.filename,ext,os.path.getsize(fp)))
    fid=cur.lastrowid; c.commit(); c.close()
    return jsonify({'id':fid,'filename':fn,'original_name':f.filename}),201

@app.route('/api/uploads/<filename>')
@require_auth
def serve_upload(filename): return send_from_directory(UPLOAD_DIR,filename)

# ══════════════════════════════
# STAFF
# ══════════════════════════════
@app.route('/api/staff')
@require_auth
def get_staff():
    c=get_db()
    rows=c.execute('SELECT * FROM users WHERE active=1 ORDER BY name').fetchall()
    result=[]
    for r in rows:
        d=dict(r); d.pop('password_hash',None)
        d['children_count']=c.execute('SELECT COUNT(*) FROM children WHERE assigned_leidster_id=? AND active=1',(r['id'],)).fetchone()[0]
        result.append(d)
    c.close(); return jsonify(result)

@app.route('/api/staff', methods=['POST'])
@require_admin
def add_staff():
    d=request.get_json(); pw=d.get('password','welkom123')
    ph=hashlib.sha256(f'{pw}{SECRET}'.encode()).hexdigest()
    name=d['name']; initials=''.join(w[0].upper() for w in name.split()[:2])
    c=get_db(); cur=c.execute('INSERT INTO users(name,email,password_hash,role,initials,color,contract_hours,vacation_hours_total)VALUES(?,?,?,?,?,?,?,?)',
        (name,d['email'],ph,d.get('role','staff'),initials,d.get('color','#6366f1'),d.get('contract_hours',32),d.get('vacation_hours',160)))
    uid=cur.lastrowid; c.commit(); c.close()
    log_action(request.user['id'],'Medewerker toegevoegd',name); return jsonify({'id':uid}),201

@app.route('/api/staff/<int:uid>/children')
@require_auth
def staff_children(uid):
    c=get_db()
    kids=c.execute('SELECT * FROM children WHERE assigned_leidster_id=? AND active=1 ORDER BY name',(uid,)).fetchall()
    result=[]
    for ch in kids:
        d=dict(ch)
        try: d['days']=json.loads(d['days'])
        except: pass
        d['obs_status'],d['last_obs'],d['next_obs_due']=calc_obs_status(d['id'],c)
        result.append(d)
    c.close(); return jsonify(result)

# ══════════════════════════════
# SHIFTS
# ══════════════════════════════
@app.route('/api/shifts')
@require_auth
def get_shifts():
    fr=request.args.get('from'); to=request.args.get('to'); uid_filter=request.args.get('user_id')
    role=request.user['role']; uid=request.user['id']
    c=get_db()
    q='SELECT s.*,u.name as user_name,u.color,u.initials FROM shifts s JOIN users u ON s.user_id=u.id WHERE 1=1'
    p=[]
    if role!='admin': q+=' AND s.user_id=?'; p.append(uid)
    elif uid_filter: q+=' AND s.user_id=?'; p.append(uid_filter)
    if fr: q+=' AND s.shift_date>=?'; p.append(fr)
    if to: q+=' AND s.shift_date<=?'; p.append(to)
    q+=' ORDER BY s.shift_date,u.name'
    rows=c.execute(q,p).fetchall(); c.close(); return jsonify([dict(r) for r in rows])

@app.route('/api/shifts', methods=['POST'])
@require_auth
def add_shift():
    d=request.get_json(); role=request.user['role']; uid=request.user['id']
    target_uid=d.get('user_id',uid)
    if role!='admin' and int(target_uid)!=uid: return jsonify({'error':'Alleen eigen diensten toevoegen'}),403
    c=get_db(); cur=c.execute('INSERT INTO shifts(user_id,shift_date,shift_type,start_time,end_time,notes)VALUES(?,?,?,?,?,?)',
        (target_uid,d['shift_date'],d.get('shift_type','werk'),d.get('start_time'),d.get('end_time'),d.get('notes')))
    sid=cur.lastrowid; c.commit(); c.close(); return jsonify({'id':sid}),201

@app.route('/api/shifts/auto-schedule', methods=['POST'])
@require_admin
def auto_schedule():
    d=request.get_json(); ws=d.get('week_start',date.today().isoformat())
    start=datetime.strptime(ws,'%Y-%m-%d').date()
    yw=start.isocalendar()[:2]; yr,wk=yw
    c=get_db()
    avail=c.execute('SELECT * FROM weekly_availability WHERE year=? AND week_number=?',(yr,wk)).fetchall()
    if not avail:
        avail=c.execute('SELECT DISTINCT user_id,day_of_week,session FROM weekly_availability WHERE year=? ORDER BY user_id,day_of_week',(yr,)).fetchall()
    created=0
    for day_off in range(5):
        sd=(start+timedelta(days=day_off)).isoformat()
        for av in avail:
            if av['day_of_week']!=day_off: continue
            if c.execute('SELECT id FROM shifts WHERE user_id=? AND shift_date=?',(av['user_id'],sd)).fetchone(): continue
            st='07:30' if av['session']=='ochtend' else '12:00'
            et='13:00' if av['session']=='ochtend' else '18:30'
            c.execute('INSERT INTO shifts(user_id,shift_date,shift_type,start_time,end_time,notes)VALUES(?,?,?,?,?,?)',(av['user_id'],sd,'werk',st,et,'Auto-gepland'))
            created+=1
    c.commit(); c.close()
    log_action(request.user['id'],'Rooster auto-gegenereerd',f'{created} diensten')
    return jsonify({'created':created,'message':f'{created} diensten ingepland'})

# ══════════════════════════════
# LEAVE
# ══════════════════════════════
@app.route('/api/leave')
@require_auth
def get_leave():
    c=get_db(); uid=request.user['id']; role=request.user['role']
    if role=='admin':
        rows=c.execute('SELECT lr.*,u.name as user_name,u.initials,u.color FROM leave_requests lr JOIN users u ON lr.user_id=u.id ORDER BY lr.created_at DESC').fetchall()
    else:
        rows=c.execute('SELECT lr.*,u.name as user_name,u.initials,u.color FROM leave_requests lr JOIN users u ON lr.user_id=u.id WHERE lr.user_id=? ORDER BY lr.created_at DESC',(uid,)).fetchall()
    c.close(); return jsonify([dict(r) for r in rows])

@app.route('/api/leave', methods=['POST'])
@require_auth
def add_leave():
    d=request.get_json(); uid=request.user['id']
    fd=datetime.strptime(d['from_date'],'%Y-%m-%d'); td=datetime.strptime(d['to_date'],'%Y-%m-%d')
    days=max(1,(td-fd).days+1)
    c=get_db(); cur=c.execute('INSERT INTO leave_requests(user_id,leave_type,from_date,to_date,days,notes)VALUES(?,?,?,?,?,?)',
        (uid,d.get('leave_type','vakantie'),d['from_date'],d['to_date'],days,d.get('notes','')))
    lid=cur.lastrowid; c.commit(); c.close()
    log_action(uid,'Verlofaanvraag ingediend',f'{d["from_date"]} t/m {d["to_date"]}')
    return jsonify({'id':lid}),201

@app.route('/api/leave/<int:lid>/review', methods=['PATCH'])
@require_admin
def review_leave(lid):
    d=request.get_json(); action=d.get('action')
    if action not in ('approve','deny'): return jsonify({'error':'Invalid'}),400
    status='approved' if action=='approve' else 'denied'
    c=get_db(); lr=c.execute('SELECT * FROM leave_requests WHERE id=?',(lid,)).fetchone()
    c.execute('UPDATE leave_requests SET status=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?',(status,request.user['id'],lid))
    if action=='approve' and lr: c.execute('UPDATE users SET vacation_hours_used=vacation_hours_used+? WHERE id=?',(lr['days']*8,lr['user_id']))
    c.commit(); c.close(); return jsonify({'status':status})

# ══════════════════════════════
# WEEKLY AVAILABILITY
# ══════════════════════════════
@app.route('/api/availability/weekly')
@require_auth
def get_weekly_avail():
    yr=request.args.get('year',date.today().year); uid_p=request.args.get('user_id')
    uid=request.user['id']; role=request.user['role']
    target=uid_p if (role=='admin' and uid_p) else uid
    c=get_db()
    rows=c.execute('SELECT * FROM weekly_availability WHERE user_id=? AND year=? ORDER BY week_number,day_of_week',(target,yr)).fetchall()
    c.close(); return jsonify([dict(r) for r in rows])

@app.route('/api/availability/weekly', methods=['POST'])
@require_auth
def set_weekly_avail():
    d=request.get_json(); uid=request.user['id']
    weeks=d.get('weeks',[]); entries=d.get('entries',[]); yr=d.get('year',date.today().year)
    c=get_db()
    for wk in weeks:
        c.execute('DELETE FROM weekly_availability WHERE user_id=? AND week_number=? AND year=?',(uid,wk,yr))
        for e in entries:
            c.execute('INSERT OR IGNORE INTO weekly_availability(user_id,week_number,year,day_of_week,session)VALUES(?,?,?,?,?)',(uid,wk,yr,e['day_of_week'],e['session']))
    c.commit(); c.close()
    log_action(uid,'Beschikbaarheid opgeslagen',f'Weken {weeks} jaar {yr}')
    return jsonify({'message':'Opgeslagen'})

# ══════════════════════════════
# WAITLIST
# ══════════════════════════════
@app.route('/api/waitlist')
@require_auth
def get_waitlist():
    c=get_db()
    rows=c.execute('SELECT * FROM waitlist ORDER BY priority_score DESC, created_at ASC').fetchall()
    result=[]
    for r in rows:
        d=dict(r)
        try: d['days']=json.loads(d['days'])
        except: pass
        result.append(d)
    c.close(); return jsonify(result)

@app.route('/api/waitlist', methods=['POST'])
@require_auth
def add_waitlist():
    d=request.get_json(); c=get_db()
    days=json.dumps(d.get('days',[0,0,0,0,0]))
    cur=c.execute('''INSERT INTO waitlist(list_type,parent_name,parent2_name,email,phone,address,bsn_parent,iban,child_name,child_dob,bsn_child,desired_start,days,contract_type,opvang_type,notes)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (d.get('list_type','extern'),d['parent_name'],d.get('parent2_name'),d['email'],d.get('phone'),d.get('address'),d.get('bsn_parent'),d.get('iban'),d['child_name'],d.get('child_dob'),d.get('bsn_child'),d.get('desired_start'),days,d.get('contract_type','52weken'),d.get('opvang_type','KDV'),d.get('notes')))
    wid=cur.lastrowid
    # Score
    row=dict(c.execute('SELECT * FROM waitlist WHERE id=?',(wid,)).fetchone())
    try: row['days']=json.loads(row['days'])
    except: pass
    score=score_waitlist_child(row,c)
    c.execute('UPDATE waitlist SET priority_score=? WHERE id=?',(score,wid))
    c.commit(); c.close()
    log_action(request.user['id'],'Wachtlijstaanmelding',d['child_name'])
    return jsonify({'id':wid,'priority_score':score}),201

@app.route('/api/waitlist/<int:wid>', methods=['PATCH'])
@require_auth
def update_waitlist(wid):
    d=request.get_json(); c=get_db()
    fields=[]; vals=[]
    allowed=['status','notes','proposal_deadline','list_type','days','priority_score']
    for f in allowed:
        if f in d:
            fields.append(f'{f}=?')
            vals.append(json.dumps(d[f]) if isinstance(d[f],list) else d[f])
    if not fields: return jsonify({'error':'No fields'}),400
    vals.append(wid)
    c.execute(f'UPDATE waitlist SET {",".join(fields)} WHERE id=?',vals)
    c.commit(); c.close(); return jsonify({'message':'Updated'})

@app.route('/api/waitlist/<int:wid>/propose', methods=['POST'])
@require_admin
def send_proposal(wid):
    d=request.get_json(); deadline=d.get('deadline',(date.today()+timedelta(days=7)).isoformat())
    c=get_db()
    c.execute('UPDATE waitlist SET status="voorstel_verstuurd",proposal_deadline=?,proposal_sent_at=CURRENT_TIMESTAMP WHERE id=?',(deadline,wid))
    wl=c.execute('SELECT child_name,parent_name FROM waitlist WHERE id=?',(wid,)).fetchone()
    c.commit(); c.close()
    if wl: log_action(request.user['id'],'Plaatsingsvoorstel verstuurd',f'{wl["child_name"]} — deadline {deadline}')
    return jsonify({'message':'Voorstel verstuurd','deadline':deadline})

@app.route('/api/waitlist/matches')
@require_admin
def waitlist_matches():
    c=get_db()
    rows=c.execute("SELECT * FROM waitlist WHERE status='wachtend' ORDER BY priority_score DESC,created_at ASC").fetchall()
    result=[]
    for r in rows:
        d=dict(r)
        try: d['days']=json.loads(d['days'])
        except: pass
        result.append(d)
    c.close(); return jsonify(result)

# ══════════════════════════════
# CONTACTS & TOURS
# ══════════════════════════════
@app.route('/api/contacts')
@require_auth
def get_contacts():
    c=get_db()
    rows=c.execute('SELECT co.*,w.child_name,w.status as wl_status FROM contacts co LEFT JOIN waitlist w ON co.waitlist_id=w.id ORDER BY co.created_at DESC').fetchall()
    c.close(); return jsonify([dict(r) for r in rows])

@app.route('/api/contacts', methods=['POST'])
@require_auth
def add_contact():
    d=request.get_json(); c=get_db()
    cur=c.execute('INSERT INTO contacts(name,email,phone,status,waitlist_id,notes)VALUES(?,?,?,?,?,?)',
        (d['name'],d.get('email'),d.get('phone'),d.get('status','niet_ingeschreven'),d.get('waitlist_id'),d.get('notes')))
    cid=cur.lastrowid; c.commit(); c.close()
    log_action(request.user['id'],'Contact toegevoegd',d['name']); return jsonify({'id':cid}),201

@app.route('/api/contacts/<int:cid>', methods=['PATCH'])
@require_auth
def update_contact(cid):
    d=request.get_json(); c=get_db()
    fields=[]; vals=[]
    for f in ['name','email','phone','status','notes','waitlist_id']:
        if f in d: fields.append(f'{f}=?'); vals.append(d[f])
    if fields:
        vals.append(cid); c.execute(f'UPDATE contacts SET {",".join(fields)} WHERE id=?',vals)
        c.commit()
    c.close(); return jsonify({'message':'Updated'})

@app.route('/api/tours')
@require_auth
def get_tours():
    c=get_db()
    rows=c.execute('SELECT t.*,co.name as contact_name,co.email,co.phone,u.name as guide_name FROM tours t LEFT JOIN contacts co ON t.contact_id=co.id LEFT JOIN users u ON t.guide_id=u.id ORDER BY t.tour_date DESC,t.tour_time').fetchall()
    c.close(); return jsonify([dict(r) for r in rows])

@app.route('/api/tours', methods=['POST'])
@require_auth
def add_tour():
    d=request.get_json(); c=get_db()
    cur=c.execute('INSERT INTO tours(contact_id,tour_date,tour_time,guide_id,attendees,status,notes)VALUES(?,?,?,?,?,?,?)',
        (d.get('contact_id'),d['tour_date'],d['tour_time'],d.get('guide_id',request.user['id']),d.get('attendees',1),d.get('status','gepland'),d.get('notes')))
    tid=cur.lastrowid; c.commit()
    log_action(request.user['id'],'Rondleiding ingepland',f'{d["tour_date"]} {d["tour_time"]}')
    c.close(); return jsonify({'id':tid}),201

@app.route('/api/tours/<int:tid>', methods=['PATCH'])
@require_auth
def update_tour(tid):
    d=request.get_json(); c=get_db()
    fields=[]; vals=[]
    for f in ['status','notes','tour_date','tour_time','guide_id','attendees']:
        if f in d: fields.append(f'{f}=?'); vals.append(d[f])
    if fields:
        vals.append(tid); c.execute(f'UPDATE tours SET {",".join(fields)} WHERE id=?',vals); c.commit()
    c.close(); return jsonify({'message':'Updated'})

# ══════════════════════════════
# STATS
# ══════════════════════════════
@app.route('/api/stats/hours')
@require_auth
def hours_stats():
    c=get_db()
    staff=c.execute('SELECT * FROM users WHERE active=1 ORDER BY name').fetchall()
    result=[]
    for s in staff:
        d=dict(s); d.pop('password_hash',None)
        exp=round(s['contract_hours']*4.3)
        d['expected_hours']=exp; d['saldo']=s['worked_hours_month']-exp
        d['vacation_left']=s['vacation_hours_total']-s['vacation_hours_used']
        result.append(d)
    c.close(); return jsonify(result)

@app.route('/api/bkr/calculate', methods=['POST'])
@require_admin
def bkr_calculate():
    d=request.get_json()
    counts={'0-1':d.get('age_0_1',0),'1-2':d.get('age_1_2',0),'2-3':d.get('age_2_3',0),'3-4':d.get('age_3_4',0),'bso':d.get('age_4_12',0)}
    ratios={'0-1':3,'1-2':5,'2-3':6,'3-4':8,'bso':10}
    total=0; breakdown={}
    for age,count in counts.items():
        if count>0:
            req=-(-count//ratios[age]); breakdown[age]={'children':count,'ratio':ratios[age],'required':req}; total+=req
    present=d.get('present',0); half=-(-total//2)
    status='ok' if present>=total else ('three_hour_rule' if present>=half else 'violation')
    return jsonify({'required':total,'present':present,'status':status,'breakdown':breakdown})

init_db()

if __name__ == '__main__':
    port=int(os.environ.get('PORT',5000))
    print(f'🚀 KinderKompas v2 → http://localhost:{port}')
    app.run(host='0.0.0.0',port=port,debug=False)
