from pss.core.passwords import generate_password,generate_passphrase,analyze_password
def test_generator():
 p=generate_password(24); assert len(p)==24; assert any(c.islower() for c in p); assert any(c.isupper() for c in p); assert any(c.isdigit() for c in p)
def test_passphrase(): assert len(generate_passphrase(5).split('-'))==5
def test_analyzer(): assert 0<=analyze_password('example-password-phrase-123')['score']<=4
