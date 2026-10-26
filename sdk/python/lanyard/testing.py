from .client import Lanyard


class LanyardTestHarness:
    def __init__(self):
        self.client = Lanyard("http://lanyard.invalid", "http://lanyard.invalid")
