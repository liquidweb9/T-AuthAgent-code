from secagent.auth.canon import canon, policy_hash, sha256


def test_canon_is_deterministic():
    a = {"b": 2, "a": 1}
    b = {"a": 1, "b": 2}
    assert canon(a) == canon(b)


def test_canon_nested_keys_sorted():
    a = {"z": {"q": 1, "p": 2}, "a": [3, 2, 1]}
    b = {"a": [3, 2, 1], "z": {"p": 2, "q": 1}}
    assert canon(a) == canon(b)


def test_policy_hash_stable_across_tuple_lists():
    p1 = {"read_email": [(100, 0, {"type": "object"}, 0)]}
    p2 = {"read_email": [(100, 0, {"type": "object"}, 0)]}
    assert policy_hash(p1) == policy_hash(p2)


def test_policy_hash_changes_on_condition_change():
    p1 = {"read_email": [(100, 0, {"type": "object"}, 0)]}
    p2 = {"read_email": [(100, 0, {"type": "string"}, 0)]}
    assert policy_hash(p1) != policy_hash(p2)


def test_policy_hash_none_distinct():
    assert policy_hash(None) != policy_hash({})


def test_sha256_length():
    assert len(sha256(b"x")) == 32
