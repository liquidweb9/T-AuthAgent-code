from secagent.auth.threshold_sig import combine, setup, sign_share, verify


def test_t_of_n_passes():
    g, sh = setup(n=5, t=3)
    msg = b"abc"
    sig = combine([sign_share(s, msg) for s in sh[:3]])
    assert verify(g, msg, sig, t=3)


def test_t_minus_one_fails():
    g, sh = setup(n=5, t=3)
    msg = b"abc"
    sig = combine([sign_share(s, msg) for s in sh[:2]])
    assert not verify(g, msg, sig, t=3)


def test_message_substitution_fails():
    g, sh = setup(n=5, t=3)
    sig = combine([sign_share(s, b"original") for s in sh[:3]])
    assert not verify(g, b"tampered", sig, t=3)


def test_extra_signatures_allowed():
    g, sh = setup(n=5, t=3)
    msg = b"abc"
    sig = combine([sign_share(s, msg) for s in sh[:4]])
    assert verify(g, msg, sig, t=3)


def test_duplicate_index_does_not_inflate_count():
    g, sh = setup(n=5, t=3)
    msg = b"abc"
    # Same signer index twice + one other = only 2 distinct
    parts = [sign_share(sh[0], msg), sign_share(sh[0], msg), sign_share(sh[1], msg)]
    sig = combine(parts)
    assert not verify(g, msg, sig, t=3)


def test_wrong_share_pk_fails():
    g1, sh1 = setup(n=5, t=3)
    g2, _ = setup(n=5, t=3)
    msg = b"abc"
    sig = combine([sign_share(s, msg) for s in sh1[:3]])
    # Verify against a *different* group key: must fail (different pks)
    assert not verify(g2, msg, sig, t=3)


def test_out_of_range_index_rejected():
    from secagent.auth.threshold_sig import CombinedSig, SignatureShare
    g, sh = setup(n=3, t=2)
    msg = b"abc"
    good = sign_share(sh[0], msg)
    bad = SignatureShare(index=99, sig=good.sig)  # nonexistent slot
    sig = CombinedSig((good, bad))
    assert not verify(g, msg, sig, t=2)
