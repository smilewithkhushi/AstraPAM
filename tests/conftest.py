import pytest
import core.schemas as _schemas
import core.broker as _broker
import core.crypto as _crypto
import core.reconcile as _reconcile


@pytest.fixture()
def db(tmp_path, monkeypatch):
    path = str(tmp_path / "test.db")
    for mod in (_schemas, _broker, _crypto, _reconcile):
        monkeypatch.setattr(mod, "DB_PATH", path)
    _schemas.init_db()
    return path
