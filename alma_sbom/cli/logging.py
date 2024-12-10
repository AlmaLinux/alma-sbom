from logging import DEBUG, INFO, WARNING, basicConfig, getLogger, Logger

APPNAME = 'alma-sbom'

class Logging():
    FORMAT: str = '%(asctime)s %(name)s: [%(levelname)s] %(message)s'
    DATEFMT: str = '%b %d %H:%M:%S'
    loglevel: int = INFO

    def __init__(self, loglevel: int) -> None:
        if loglevel is not None:
            self.loglevel = loglevel

        self.setup()

    def setup(self) -> None:
        basicConfig(
            format=self.FORMAT,
            datefmt=self.DATEFMT,
            level=self.loglevel,
        )

