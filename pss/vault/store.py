import json, os, secrets, sqlite3
from pathlib import Path
from pss.security.crypto import derive_key, encrypt, decrypt
class VaultError(Exception): pass
class VaultStore:
 def __init__(self,db_path=None):
  self.path=Path(db_path or Path(__file__).resolve().parents[2]/'instance'/'vault.db'); self.path.parent.mkdir(parents=True,exist_ok=True); self._key=None; self._init()
 def _connect(self):
  c=sqlite3.connect(self.path); c.row_factory=sqlite3.Row; return c
 def _init(self):
  with self._connect() as c:
   c.execute('CREATE TABLE IF NOT EXISTS vault_meta(id INTEGER PRIMARY KEY CHECK(id=1),salt BLOB NOT NULL,nonce BLOB NOT NULL,wrapped_key BLOB NOT NULL,kdf_time INTEGER NOT NULL,kdf_memory INTEGER NOT NULL,kdf_parallelism INTEGER NOT NULL)')
   c.execute('CREATE TABLE IF NOT EXISTS entries(id TEXT PRIMARY KEY,nonce BLOB NOT NULL,ciphertext BLOB NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)')
 def exists(self):
  with self._connect() as c: return c.execute('SELECT 1 FROM vault_meta WHERE id=1').fetchone() is not None
 def create(self,password):
  if self.exists(): raise VaultError('Vault already exists.')
  if len(password)<14: raise VaultError('Use at least 14 characters for the vault master password.')
  salt=os.urandom(16); data_key=os.urandom(32); kek=derive_key(password,salt); nonce,wrapped=encrypt(kek,data_key,b'pss-vault-key-v1')
  with self._connect() as c: c.execute('INSERT INTO vault_meta VALUES(1,?,?,?,?,?,?)',(salt,nonce,wrapped,3,65536,2))
  self._key=data_key
 def unlock(self,password):
  with self._connect() as c: r=c.execute('SELECT * FROM vault_meta WHERE id=1').fetchone()
  if not r: raise VaultError('Vault has not been created.')
  kek=derive_key(password,r['salt'],r['kdf_time'],r['kdf_memory'],r['kdf_parallelism'])
  try: self._key=decrypt(kek,r['nonce'],r['wrapped_key'],b'pss-vault-key-v1')
  except Exception as e: self._key=None; raise VaultError('Incorrect master password or damaged vault.') from e
 def lock(self): self._key=None
 def _check(self):
  if self._key is None: raise VaultError('Unlock the vault first.')
 def add(self,title,username,password,url='',notes=''):
  self._check(); i=secrets.token_hex(16); p=json.dumps({'title':title,'username':username,'password':password,'url':url,'notes':notes}).encode(); n,cipher=encrypt(self._key,p,i.encode())
  with self._connect() as c: c.execute('INSERT INTO entries(id,nonce,ciphertext) VALUES(?,?,?)',(i,n,cipher))
  return i
 def list_entries(self):
  self._check()
  with self._connect() as c: rows=c.execute('SELECT id,nonce,ciphertext FROM entries ORDER BY updated_at DESC').fetchall()
  out=[]
  for r in rows:
   try: d=json.loads(decrypt(self._key,r['nonce'],r['ciphertext'],r['id'].encode()))
   except Exception as e: raise VaultError('Vault entry authentication failed.') from e
   d['id']=r['id']; out.append(d)
  return out
 def delete(self,i):
  self._check()
  with self._connect() as c: c.execute('DELETE FROM entries WHERE id=?',(i,))
