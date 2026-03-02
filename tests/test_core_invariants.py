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
