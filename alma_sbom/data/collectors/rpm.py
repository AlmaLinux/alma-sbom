from rpm import TransactionSet

from alma_sbom.models import Package

class RpmCollector:
    ts: TransactionSet

    def __init__(self):
        self.ts = TransactionSet()

    def collect_package_from_file(self, path: str) -> Package:
        pass

