import argparse,getpass
from pss.core.passwords import generate_password,generate_passphrase,analyze_password
from pss.vault.store import VaultStore,VaultError
def main():
 p=argparse.ArgumentParser(prog='pss',description='Local Password Security Suite'); s=p.add_subparsers(dest='cmd',required=True)
 g=s.add_parser('generate'); g.add_argument('--length',type=int,default=20); g.add_argument('--no-symbols',action='store_true')
 s.add_parser('passphrase'); s.add_parser('analyze'); s.add_parser('vault-create'); s.add_parser('vault-list'); s.add_parser('vault-add'); s.add_parser('vault-delete')
 a=p.parse_args()
 if a.cmd=='generate': print(generate_password(a.length,symbols=not a.no_symbols)); return
 if a.cmd=='passphrase': print(generate_passphrase()); return
 if a.cmd=='analyze':
  r=analyze_password(getpass.getpass('Password to analyze (not saved): ')); print(f"Strength: {r['label']} ({r['score']}/4)"); print('\n'.join(r['suggestions'])); return
 v=VaultStore()
 if a.cmd=='vault-create': v.create(getpass.getpass('New vault master password: ')); print('Vault created.'); return
 if not v.exists(): print('Create a vault first: python cli.py vault-create'); return
 v.unlock(getpass.getpass('Vault master password: '))
 try:
  if a.cmd=='vault-list':
   for x in v.list_entries(): print(x['id'],x['title'],x['username'])
  elif a.cmd=='vault-add': v.add(input('Title: '),input('Username: '),getpass.getpass('Password: '),input('URL (optional): ')); print('Encrypted entry saved.')
  elif a.cmd=='vault-delete': v.delete(input('Entry ID: ')); print('Deleted if entry existed.')
 finally: v.lock()
if __name__=='__main__': main()
