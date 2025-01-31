from rpm import TransactionSet

from alma_sbom.data.models import Package

class RpmCollector:
    ts: TransactionSet

    def __init__(self):
        self.ts = TransactionSet()

    ### TODO:
    # Implement below function
    def collect_package_from_file(self, path: str) -> Package:
        pass

