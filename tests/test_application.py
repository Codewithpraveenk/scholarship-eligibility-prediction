"""Real HTTP integration tests against an isolated SQLite database."""
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request


class ApplicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0))
            cls.port = sock.getsockname()[1]
        cls.base = f'http://127.0.0.1:{cls.port}'
        env = {**os.environ,'DATABASE_URL':os.environ.get('TEST_DATABASE_URL',''),'DATABASE_PATH':str(Path(cls.temp.name)/'test.db'),'ADMIN_EMAIL':'admin@example.org','ADMIN_PASSWORD':'Admin-test-password-2026','APP_ENV':'test','APP_ORIGIN':cls.base}
        cls.process = subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port',str(cls.port)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                urllib.request.urlopen(cls.base+'/health',timeout=1).close()
                break
            except OSError:
                time.sleep(.1)
        else:
            cls.process.terminate()
            raise RuntimeError('Test server did not start')

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=10)
        cls.temp.cleanup()

    def setUp(self):
        self.client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.csrf=''

    def request(self,path,method='GET',body=None,csrf=True,headers=None):
        request=urllib.request.Request(self.base+path,method=method,data=json.dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json',**({'X-CSRF-Token':self.csrf} if csrf else {}),**(headers or {})})
        try:
            response=self.client.open(request)
        except urllib.error.HTTPError as error:
            response=error
        with response:
            raw=response.read()
            try: result=json.loads(raw)
            except ValueError: result=raw.decode()
            return response.status,result,response.headers

    def login(self,admin=False):
        email='admin@example.org' if admin else f'{time.time_ns()}@example.org'
        status,user,_=self.request('/api/auth/login' if admin else '/api/auth/register','POST',{'email':email,'password':'Admin-test-password-2026' if admin else 'Student-test-password','name':'Test Student'})
        self.assertEqual(status,200,user)
        self.csrf=user['csrf']
        return user

    def policy(self,**changes):
        return dict(title='Verified Test Scholarship',provider='Test Foundation',amount=50000,min_marks=80,max_income=300000,level='undergraduate',deadline='2099-12-31',source_url='https://example.org/scholarship',active=True,**changes)

    def test_01_health_and_security_headers(self):
        status,body,headers=self.request('/health')
        self.assertEqual((status,body),(200,{'status':'ok'}))
        self.assertEqual(headers['X-Content-Type-Options'],'nosniff')
        self.assertIn("script-src 'self'",headers['Content-Security-Policy'])

    def test_00_unpublished_policies_are_not_assessed(self):
        self.assertEqual(self.request('/api/scholarships')[1],[])
        self.login()
        self.assertEqual(self.request('/api/assessments','POST',{'marks':95,'annual_income':100000,'level':'undergraduate'})[0],409)

    def test_02_home_and_assets(self):
        for path,content in [('/','ScholarPath'),('/static/app.js','loadCatalog'),('/static/style.css',':root')]:
            status,body,_=self.request(path)
            self.assertEqual(status,200)
            self.assertIn(content,body)

    def test_03_private_endpoints(self):
        for path in ['/api/me','/api/assessments','/api/admin/audit']:
            self.assertEqual(self.request(path)[0],401)

    def test_04_account_and_logout(self):
        user=self.login()
        self.assertEqual(self.request('/api/me')[1]['email'],user['email'])
        self.assertEqual(self.request('/api/logout','POST',{})[0],200)
        self.assertEqual(self.request('/api/me')[0],401)

    def test_05_password_validation_and_invalid_login(self):
        self.assertEqual(self.request('/api/auth/register','POST',{'email':'x@example.org','password':'short'})[0],422)
        self.assertEqual(self.request('/api/auth/login','POST',{'email':'missing@example.org','password':'long-wrong-password'})[0],401)

    def test_06_csrf_and_origin_rejection(self):
        self.login()
        self.assertEqual(self.request('/api/logout','POST',{},csrf=False)[0],403)
        self.assertEqual(self.request('/api/logout','POST',{},headers={'Origin':'https://attacker.example'})[0],403)

    def test_07_student_cannot_manage_rules(self):
        self.login()
        self.assertEqual(self.request('/api/admin/scholarships','POST',self.policy())[0],403)
        self.assertEqual(self.request('/api/admin/audit')[0],403)

    def test_08_admin_publish_and_audit(self):
        self.login(admin=True)
        status,result,_=self.request('/api/admin/scholarships','POST',self.policy())
        self.assertEqual(status,201,result)
        self.assertGreater(result['id'],0)
        self.assertEqual(self.request('/api/admin/audit')[1][0]['action'],'create_policy')

    def test_09_assessment_boundaries_and_ownership(self):
        self.login(admin=True)
        self.request('/api/admin/scholarships','POST',self.policy())
        self.request('/api/logout','POST',{})
        self.login()
        status,result,_=self.request('/api/assessments','POST',{'marks':80,'annual_income':300000,'level':'undergraduate'})
        self.assertEqual(status,201,result)
        self.assertTrue(all(r['eligible'] for r in result['results']))
        self.assertEqual(len(self.request('/api/assessments')[1]),1)
        assessment=result['id']
        self.request('/api/logout','POST',{})
        self.login()
        self.assertEqual(self.request('/api/assessments')[1],[])
        self.assertEqual(self.request(f'/api/assessments/{assessment}','DELETE')[0],404)

    def test_10_ineligible_explanations(self):
        self.login()
        status,result,_=self.request('/api/assessments','POST',{'marks':79,'annual_income':300001,'level':'school'})
        self.assertEqual(status,201,result)
        self.assertTrue(all(not r['eligible'] for r in result['results']))
        self.assertTrue(all(sum(not c['passed'] for c in r['checks'])==3 for r in result['results']))

    def test_11_invalid_profile(self):
        self.login()
        for change in [{'marks':101},{'marks':-1},{'annual_income':-1},{'annual_income':2.5},{'level':'other'}]:
            body={'marks':85,'annual_income':200000,'level':'undergraduate',**change}
            self.assertEqual(self.request('/api/assessments','POST',body)[0],422)

    def test_12_publish_requires_source(self):
        self.login(admin=True)
        body=self.policy();body['source_url']=''
        self.assertEqual(self.request('/api/admin/scholarships','POST',body)[0],422)
        body['source_url']='javascript:alert(1)'
        self.assertEqual(self.request('/api/admin/scholarships','POST',body)[0],422)

    def test_13_versioning_and_snapshot(self):
        self.login(admin=True)
        body=self.policy()
        _,created,_=self.request('/api/admin/scholarships','POST',body)
        _,assessment,_=self.request('/api/assessments','POST',{'marks':85,'annual_income':200000,'level':'undergraduate'})
        body['min_marks']=95
        self.assertEqual(self.request('/api/admin/scholarships/'+str(created['id']),'PUT',body)[0],200)
        saved=self.request('/api/assessments')[1][0]
        old=next(p for p in saved['results'] if p['id']==created['id'])
        self.assertEqual(old['version'],1)
        self.assertTrue(old['eligible'])
        self.assertEqual(self.request(f'/api/assessments/{assessment["id"]}','DELETE')[0],200)

    def test_14_rate_limit(self):
        body={'email':'limited@example.org','password':'incorrect-password'}
        for _ in range(10):
            self.assertEqual(self.request('/api/auth/login','POST',body)[0],401)
        self.assertEqual(self.request('/api/auth/login','POST',body)[0],429)

    def test_15_expired_policy_and_study_levels(self):
        self.login(admin=True)
        body=self.policy();body['deadline']='2020-01-01';body['level']='any'
        _,created,_=self.request('/api/admin/scholarships','POST',body)
        _,result,_=self.request('/api/assessments','POST',{'marks':100,'annual_income':0,'level':'school'})
        expired=next(p for p in result['results'] if p['id']==created['id'])
        self.assertFalse(expired['eligible'])
        self.assertTrue(expired['checks'][2]['passed'])
        self.assertFalse(expired['checks'][3]['passed'])

    def test_16_duplicate_registration_and_invalid_policy(self):
        user=self.login()
        self.assertEqual(self.request('/api/auth/register','POST',{'email':user['email'],'password':'Student-test-password'})[0],409)
        self.request('/api/logout','POST',{})
        self.login(admin=True)
        body=self.policy();body['deadline']='not-a-date'
        self.assertEqual(self.request('/api/admin/scholarships','POST',body)[0],422)

if __name__=='__main__':
    unittest.main()
