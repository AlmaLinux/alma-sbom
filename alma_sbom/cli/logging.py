from logging import basicConfig
from typing import ClassVar

class Logging():
    FORMAT: ClassVar[str] = '%(asctime)s %(name)s: [%(levelname)s] %(message)s'
    DATEFMT: ClassVar[str] = '%b %d %H:%M:%S'
    loglevel: int

    def __init__(self, loglevel: int) -> None:
        self.loglevel = loglevel
        self.setup()

    def setup(self) -> None:
        basicConfig(
            format=self.FORMAT,
            datefmt=self.DATEFMT,
            level=self.loglevel,
        )

