import os
import time
from pathlib import Path
from flask import Flask,flash,jsonify,redirect,render_template,request,session,url_for
from flask_wtf.csrf import CSRFProtect
from pss.core.passwords import generate_password,generate_passphrase,analyze_password
from pss.vault.store import VaultStore,VaultError

ROOT=Path(__file__).resolve().parent
DATA=ROOT/'instance'
DATA.mkdir(exist_ok=True)
keyfile=DATA/'flask-secret.key'
if not keyfile.exists():
 keyfile.write_bytes(os.urandom(32))
try:
 os.chmod(keyfile,0o600)
except OSError:
 pass

IDLE_TIMEOUT_SECONDS=300
app=Flask(__name__)
app.config.update(
 SECRET_KEY=keyfile.read_bytes(),
 SESSION_COOKIE_HTTPONLY=True,
 SESSION_COOKIE_SAMESITE='Strict',
 PERMANENT_SESSION_LIFETIME=IDLE_TIMEOUT_SECONDS,
 SESSION_REFRESH_EACH_REQUEST=True,
 MAX_CONTENT_LENGTH=1048576
)
CSRFProtect(app)
vault=VaultStore()

def unlocked():
 return bool(session.get('vault_unlocked'))

@app.before_request
def enforce_vault_idle_timeout():
 if not unlocked():
  return None
 now=time.time()
 last_activity=session.get('vault_last_activity',now)
 if now-last_activity > IDLE_TIMEOUT_SECONDS:
  vault.lock()
  session.clear()
  if request.path.startswith('/vault') and request.endpoint not in ('setup_vault','unlock_vault'):
   flash('Vault locked after 5 minutes of inactivity. Unlock it to continue.','error')
   return redirect(url_for('unlock_vault' if vault.exists() else 'setup_vault'))
  return None
 session['vault_last_activity']=now
 return None

@app.after_request
def headers(r):
 r.headers['X-Content-Type-Options']='nosniff'
 r.headers['X-Frame-Options']='DENY'
 r.headers['Referrer-Policy']='no-referrer'
 r.headers['Cache-Control']='no-store'
 r.headers['Content-Security-Policy']="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
 return r

@app.get('/')
def home():
 return render_template('home.html',vault_exists=vault.exists(),unlocked=unlocked())

@app.route('/vault/setup',methods=['GET','POST'])
def setup_vault():
 if vault.exists():
  return redirect(url_for('unlock_vault'))
 if request.method=='POST':
  pw=request.form.get('master_password','')
  if pw!=request.form.get('confirm',''):
   flash('Passwords do not match.','error')
  else:
   try:
    vault.create(pw)
    session.clear()
    session['vault_unlocked']=True
    session['vault_last_activity']=time.time()
    session.permanent=True
    return redirect(url_for('vault_page'))
   except VaultError as e:
    flash(str(e),'error')
 return render_template('vault_setup.html')

@app.route('/vault/unlock',methods=['GET','POST'])
def unlock_vault():
 if not vault.exists():
  return redirect(url_for('setup_vault'))
 if request.method=='POST':
  try:
   vault.unlock(request.form.get('master_password',''))
   session.clear()
   session['vault_unlocked']=True
   session['vault_last_activity']=time.time()
   session.permanent=True
   return redirect(url_for('vault_page'))
  except VaultError as e:
   flash(str(e),'error')
 return render_template('vault_unlock.html')

@app.post('/vault/lock')
def lock_vault():
 vault.lock()
 session.clear()
 return redirect(url_for('home'))

@app.get('/vault')
def vault_page():
 if not unlocked():
  return redirect(url_for('unlock_vault' if vault.exists() else 'setup_vault'))
 try:
  return render_template('vault.html',entries=vault.list_entry_summaries())
 except VaultError as e:
  vault.lock()
  session.clear()
  flash(str(e),'error')
  return redirect(url_for('home'))

@app.post('/vault/add')
def add_entry():
 if not unlocked():
  return redirect(url_for('unlock_vault'))
 try:
  vault.add(request.form.get('title',''),request.form.get('username',''),request.form.get('password',''),request.form.get('url',''),request.form.get('notes',''))
  flash('Encrypted entry saved.','success')
 except Exception as e:
  flash(str(e),'error')
 return redirect(url_for('vault_page'))

@app.post('/vault/reveal/<item_id>')
def reveal_entry(item_id):
 if not unlocked():
  return jsonify({'error':'Vault is locked.'}),401
 try:
  entry=vault.get_entry(item_id)
  return jsonify({'password':entry.get('password',''),'notes':entry.get('notes','')})
 except VaultError as e:
  return jsonify({'error':str(e)}),404

@app.post('/vault/delete/<item_id>')
def delete_entry(item_id):
 if not unlocked():
  return redirect(url_for('unlock_vault'))
 vault.delete(item_id)
 return redirect(url_for('vault_page'))

@app.route('/toolkit',methods=['GET','POST'])
def toolkit():
 generated=phrase=analysis=None
 if request.method=='POST':
  try:
   action=request.form.get('action')
   if action=='generate':
    generated=generate_password(int(request.form.get('length',24)),request.form.get('lower')=='on',request.form.get('upper')=='on',request.form.get('digits')=='on',request.form.get('symbols')=='on',request.form.get('avoid_ambiguous')=='on')
   elif action=='passphrase':
    phrase=generate_passphrase(int(request.form.get('words',5)))
   elif action=='analyze':
    analysis=analyze_password(request.form.get('password',''))
  except Exception as e:
   flash(str(e),'error')
 return render_template('toolkit.html',generated=generated,phrase=phrase,analysis=analysis)

if __name__=='__main__':
 app.run(host='127.0.0.1',port=5000,debug=False)
