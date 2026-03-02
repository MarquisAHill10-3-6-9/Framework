class Core:
    """
    Minimal Core layer:
    - has an initialized flag
    - supports 'initialize()' as an explicit action
    - supports 'fingerprint()' as a stable identity snapshot
    """

    def __init__(self) -> None:
        self._initialized = True
        self._version = 1

    def is_initialized(self) -> bool:
        return self._initialized

    def identity(self) -> str:
        return "CORE"

    def initialize(self) -> None:
        self._initialized = True
        self._version += 1
    def fingerprint(self) -> tuple[int, bool]:
        return (self._version, self._initialized)
