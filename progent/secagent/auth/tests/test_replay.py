from secagent.auth.replay_store import ReplayStore


def test_first_use_succeeds():
    r = ReplayStore()
    assert r.check_and_consume(b"n1") is True


def test_second_use_rejected():
    r = ReplayStore()
    assert r.check_and_consume(b"n1") is True
    assert r.check_and_consume(b"n1") is False


def test_different_nonces_independent():
    r = ReplayStore()
    assert r.check_and_consume(b"n1") is True
    assert r.check_and_consume(b"n2") is True


def test_seen_does_not_consume():
    r = ReplayStore()
    assert r.seen(b"n1") is False
    r.mark(b"n1")
    assert r.seen(b"n1") is True
    assert r.check_and_consume(b"n1") is False
