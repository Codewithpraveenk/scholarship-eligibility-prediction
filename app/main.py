"""ScholarPath: authenticated, auditable scholarship screening."""
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ConfigDict, field_validator
from app.database import database

ROOT = Path(__file__).resolve().parent
PROD = os.environ.get('APP_ENV') == 'production'
if not os.environ.get('APP_ORIGIN') and os.environ.get('RENDER_EXTERNAL_URL'):
    os.environ['APP_ORIGIN'] = os.environ['RENDER_EXTERNAL_URL'].rstrip('/')
if PROD and not os.environ.get('APP_ORIGIN', '').startswith('https://'):
    raise RuntimeError('Production requires APP_ORIGIN set to the public HTTPS origin')
logger = logging.getLogger('scholarpath')

def initialize():
    with database() as db:
        if not db.postgres:
            db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'student');
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, expires DOUBLE PRECISION NOT NULL, csrf TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS scholarships(id INTEGER PRIMARY KEY, title TEXT NOT NULL, provider TEXT NOT NULL, amount INTEGER NOT NULL, min_marks REAL NOT NULL, max_income INTEGER NOT NULL, level TEXT NOT NULL, deadline TEXT NOT NULL, source_url TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 0, version INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS assessments(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, profile TEXT NOT NULL, results TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS attempts(key TEXT NOT NULL, created DOUBLE PRECISION NOT NULL);
        CREATE INDEX IF NOT EXISTS attempts_key ON attempts(key, created);
        ''')
        # Illustrative policies are deliberately unpublished until an administrator verifies them.
        if not db.execute('SELECT 1 FROM scholarships LIMIT 1').fetchone():
            db.executemany('INSERT INTO scholarships(title,provider,amount,min_marks,max_income,level,deadline,source_url) VALUES(?,?,?,?,?,?,?,?)', [
                ('Academic Excellence Grant','Example policy — replace before publishing',50000,85,600000,'undergraduate','2027-03-31',''),
                ('Access to Education Grant','Example policy — replace before publishing',30000,60,250000,'any','2027-03-31',''),
                ('Postgraduate Research Grant','Example policy — replace before publishing',75000,75,800000,'postgraduate','2027-03-31','')])
        email = os.environ.get('ADMIN_EMAIL', '').strip().lower()
        password = os.environ.get('ADMIN_PASSWORD', '')
        if email and password:
            if len(password) < 12:
                raise RuntimeError('ADMIN_PASSWORD must have at least 12 characters')
            db.execute('INSERT INTO users(email,name,password,role) VALUES(?,?,?,?) ON CONFLICT(email) DO NOTHING', (email,'Administrator',hash_password(password),'admin'))

def hash_password(password):
    salt = secrets.token_hex(16)
    return salt + ':' + hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1).hex()

def verify_password(password, stored):
    salt, expected = stored.split(':')
    actual = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1).hex()
    return hmac.compare_digest(actual, expected)

initialize()
app = FastAPI(title='ScholarPath API', version='1.0.0', docs_url=None if PROD else '/docs', redoc_url=None)

@app.middleware('http')
async def security(request: Request, call_next):
    if request.method in ('POST','PUT','DELETE','PATCH'):
        try:
            length = int(request.headers.get('content-length', '0'))
        except ValueError:
            return Response('Invalid content length', status_code=400)
        if length > 32768:
            return Response('Request too large', status_code=413)
        origin = request.headers.get('origin')
        allowed = os.environ.get('APP_ORIGIN', str(request.base_url).rstrip('/'))
        if origin and origin != allowed:
            return Response('Origin rejected', status_code=403)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    if request.url.path.startswith('/api'):
        response.headers['Cache-Control'] = 'no-store'
    if PROD:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

class Credentials(BaseModel):
    model_config = ConfigDict(extra='forbid')
    email: str = Field(min_length=3, max_length=254, pattern=r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
    password: str = Field(min_length=12, max_length=128)
    name: str = Field(default='Student', min_length=1, max_length=80)

class Profile(BaseModel):
    model_config = ConfigDict(extra='forbid')
    marks: float = Field(ge=0, le=100, allow_inf_nan=False)
    annual_income: int = Field(ge=0, le=100000000, strict=True)
    level: Literal['school','undergraduate','postgraduate']

class Scholarship(BaseModel):
    model_config = ConfigDict(extra='forbid')
    title: str = Field(min_length=3,max_length=160)
    provider: str = Field(min_length=3,max_length=160)
    amount: int = Field(gt=0,le=10000000)
    min_marks: float = Field(ge=0,le=100,allow_inf_nan=False)
    max_income: int = Field(ge=0,le=100000000)
    level: Literal['any','school','undergraduate','postgraduate']
    deadline: str
    source_url: str = Field(max_length=1000)
    active: bool = False

    @field_validator('deadline')
    @classmethod
    def valid_date(cls, value):
        from datetime import date
        return date.fromisoformat(value).isoformat()

    @field_validator('source_url')
    @classmethod
    def valid_url(cls,value):
        from urllib.parse import urlparse
        parsed = urlparse(value)
        if value and (parsed.scheme != 'https' or not parsed.hostname or parsed.username):
            raise ValueError('Use an official HTTPS source URL')
        return value

def current_user(request, db, admin=False):
    token = request.cookies.get('session','')
    row = db.execute('SELECT users.*,sessions.csrf FROM sessions JOIN users ON users.id=sessions.user_id WHERE token=? AND expires>?', (hashlib.sha256(token.encode()).hexdigest(),time.time())).fetchone()
    if not row:
        raise HTTPException(401,'Please sign in to continue')
    if request.method not in ('GET','HEAD') and not hmac.compare_digest(request.headers.get('x-csrf-token',''),row['csrf']):
        raise HTTPException(403,'Session verification failed. Refresh and try again.')
    if admin and row['role'] != 'admin':
        raise HTTPException(403,'Administrator access required')
    return row

def rate_limit(request, db, email):
    key = f'{request.client.host}:{email.lower()}'
    now = time.time()
    db.execute('DELETE FROM attempts WHERE created<?',(now-900,))
    if db.execute('SELECT COUNT(*) AS total FROM attempts WHERE key=?',(key,)).fetchone()['total'] >= 10:
        raise HTTPException(429,'Too many attempts. Try again in 15 minutes.')
    db.execute('INSERT INTO attempts VALUES(?,?)',(key,now))
    db.commit()

@app.post('/api/auth/{action}')
def authenticate(action: Literal['register','login'], body: Credentials, request: Request, response: Response):
    with database() as db:
        rate_limit(request, db, body.email)
        email = body.email.strip().lower()
        user = db.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
        if action == 'register':
            if user:
                raise HTTPException(409,'This email cannot be registered. Try signing in.')
            db.execute('INSERT INTO users(email,name,password) VALUES(?,?,?)',(email,body.name.strip() or 'Student',hash_password(body.password)))
            user = db.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
        elif not user or not verify_password(body.password,user['password']):
            raise HTTPException(401,'Email or password is incorrect')
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        db.execute('DELETE FROM sessions WHERE expires<?',(time.time(),))
        db.execute('INSERT INTO sessions VALUES(?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),user['id'],time.time()+86400,csrf))
        response.set_cookie('session',token,httponly=True,secure=PROD,samesite='strict',max_age=86400,path='/')
        return {'name':user['name'],'email':user['email'],'role':user['role'],'csrf':csrf}

@app.get('/api/me')
def me(request: Request):
    with database() as db:
        user = current_user(request,db)
        return {key:user[key] for key in ('name','email','role','csrf')}

@app.post('/api/logout')
def logout(request: Request,response: Response):
    with database() as db:
        current_user(request,db)
        db.execute('DELETE FROM sessions WHERE token=?',(hashlib.sha256(request.cookies.get('session','').encode()).hexdigest(),))
    response.delete_cookie('session',path='/')
    return {'ok':True}

@app.get('/api/scholarships')
def scholarships(request: Request):
    with database() as db:
        show_all = False
        if request.cookies.get('session'):
            show_all = current_user(request,db)['role']=='admin'
        return [dict(r) for r in db.execute('SELECT * FROM scholarships' + ('' if show_all else ' WHERE active=1') + ' ORDER BY amount DESC')]

def evaluate(profile, policies, today=None):
    from datetime import date
    today = today or date.today().isoformat()
    results = []
    for policy in policies:
        checks = [
            {'label':f'Marks at least {policy["min_marks"]:g}%','passed':profile.marks >= policy['min_marks']},
            {'label':f'Annual household income at most INR {policy["max_income"]:,}','passed':profile.annual_income <= policy['max_income']},
            {'label':f'Study level: {policy["level"]}','passed':policy['level'] in ('any',profile.level)},
            {'label':f'Deadline: {policy["deadline"]}','passed':policy['deadline'] >= today}]
        results.append({**dict(policy),'eligible':all(c['passed'] for c in checks),'checks':checks})
    return sorted(results,key=lambda r:(not r['eligible'],-r['amount']))

@app.post('/api/assessments',status_code=201)
def assess(body: Profile, request: Request):
    with database() as db:
        user = current_user(request,db)
        policies = db.execute('SELECT * FROM scholarships WHERE active=1').fetchall()
        if not policies:
            raise HTTPException(409,'No verified scholarships have been published yet. An administrator must publish official policies first.')
        results = evaluate(body,policies)
        cur = db.execute('INSERT INTO assessments(user_id,profile,results) VALUES(?,?,?) RETURNING id',(user['id'],body.model_dump_json(),json.dumps(results)))
        return {'id':cur.fetchone()['id'],'profile':body.model_dump(),'results':results}

@app.get('/api/assessments')
def history(request: Request):
    with database() as db:
        user = current_user(request,db)
        return [{'id':r['id'],'created_at':r['created_at'],'profile':json.loads(r['profile']),'results':json.loads(r['results'])} for r in db.execute('SELECT * FROM assessments WHERE user_id=? ORDER BY id DESC LIMIT 100',(user['id'],))]

@app.delete('/api/assessments/{assessment_id}')
def delete_assessment(assessment_id: int,request: Request):
    with database() as db:
        user = current_user(request,db)
        cur = db.execute('DELETE FROM assessments WHERE id=? AND user_id=?',(assessment_id,user['id']))
        if not cur.rowcount:
            raise HTTPException(404,'Assessment not found')
    return {'ok':True}

@app.put('/api/admin/scholarships/{policy_id}')
def update_policy(policy_id: int,body: Scholarship,request: Request):
    if body.active and not body.source_url:
        raise HTTPException(422,'An official source URL is required before publishing')
    with database() as db:
        user = current_user(request,db,admin=True)
        fields = body.model_dump()
        fields['active'] = int(fields['active'])
        cur = db.execute('UPDATE scholarships SET '+','.join(f'{key}=?' for key in fields)+', version=version+1 WHERE id=?',(*fields.values(),policy_id))
        if not cur.rowcount:
            raise HTTPException(404,'Scholarship not found')
        db.execute('INSERT INTO audit(user_id,action,details) VALUES(?,?,?)',(user['id'],'update_policy',json.dumps({'id':policy_id,**fields})))
    return {'ok':True}

@app.post('/api/admin/scholarships',status_code=201)
def create_policy(body: Scholarship,request: Request):
    if body.active and not body.source_url:
        raise HTTPException(422,'An official source URL is required before publishing')
    with database() as db:
        user = current_user(request,db,admin=True)
        fields = body.model_dump()
        fields['active'] = int(fields['active'])
        cur = db.execute('INSERT INTO scholarships('+','.join(fields)+') VALUES('+','.join('?' for _ in fields)+') RETURNING id',tuple(fields.values()))
        policy_id = cur.fetchone()['id']
        db.execute('INSERT INTO audit(user_id,action,details) VALUES(?,?,?)',(user['id'],'create_policy',json.dumps({'id':policy_id,**fields})))
        return {'id':policy_id}

@app.get('/api/admin/audit')
def audit(request: Request):
    with database() as db:
        current_user(request,db,admin=True)
        return [dict(r) for r in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 100')]

@app.get('/health')
def health():
    with database() as db:
        db.execute('SELECT 1').fetchone()
    return {'status':'ok'}

@app.get('/')
def index():
    return FileResponse(ROOT / 'static' / 'index.html')

app.mount('/static',StaticFiles(directory=ROOT / 'static'),name='static')
