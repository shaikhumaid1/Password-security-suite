import pytest
from pss.vault.store import VaultStore,VaultError
def test_roundtrip_and_wrong_password(tmp_path):
 v=VaultStore(tmp_path/'vault.db'); v.create('correct horse battery staple 2026!'); v.add('Email','student@example.test','dummy-secret'); v.lock()
 with pytest.raises(VaultError): v.unlock('incorrect password')
 v.unlock('correct horse battery staple 2026!'); assert v.list_entries()[0]['password']=='dummy-secret'; v.lock()
