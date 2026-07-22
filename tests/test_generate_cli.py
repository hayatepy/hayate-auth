"""python -m hayate_auth generate"""

import pytest

from hayate_auth.__main__ import main


def test_generate_sqlite(capsys):
    assert main(["generate", "--dialect", "sqlite"]) == 0
    out = capsys.readouterr().out
    assert 'CREATE TABLE IF NOT EXISTS "user"' in out
    assert 'CREATE TABLE IF NOT EXISTS "verification"' in out


def test_generate_d1_matches_sqlite(capsys):
    main(["generate", "--dialect", "d1"])
    d1 = capsys.readouterr().out
    main(["generate", "--dialect", "sqlite"])
    sqlite = capsys.readouterr().out
    assert d1 == sqlite


def test_unknown_dialect_errors():
    with pytest.raises(SystemExit):
        main(["generate", "--dialect", "oracle"])
