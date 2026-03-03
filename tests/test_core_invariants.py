from framework_core.core import Core


def test_core_instantiates():
    c = Core()
    assert c is not None


def test_core_initialized_flag():
    c = Core()
    assert c.is_initialized() is True


def test_core_identity():
    c = Core()
    assert c.identity() == "CORE"


def test_core_fingerprint_changes_after_initialize():
    c = Core()
    before = c.fingerprint()
    c.initialize()
    after = c.fingerprint()
    assert before != after


def test_core_ledger_records_initialize_action():
    c = Core()
    before_len = len(c.ledger())
    c.initialize()
    after = c.ledger()

    assert len(after) == before_len + 1
    assert after[-1].action == "initialize"


def test_ledger_validates():
    c = Core()
    assert c.validate_ledger() is True
    c.initialize()
    assert c.validate_ledger() is True


def test_ledger_view_is_immutable():
    c = Core()
    view = c.ledger()
    assert isinstance(view, tuple)
    # tuple has no append; this proves the public view is not mutable
    assert not hasattr(view, "append")


def test_tamper_detection_trips_validation():
    c = Core()
    c.initialize()
    assert c.validate_ledger() is True

    # Simulate a malicious change by directly tampering internal ledger
    # (Python cannot fully prevent this; we detect it.)
    first = c._ledger[0]
    c._ledger[0] = type(first)(
        ts=first.ts,
        event=first.event,
        action=first.action,
        data={"initialized": "TAMPERED"},
        fingerprint=first.fingerprint,
        prev_hash=first.prev_hash,
        entry_hash=first.entry_hash,  # keeping old hash should fail validation
    )

    assert c.validate_ledger() is False
