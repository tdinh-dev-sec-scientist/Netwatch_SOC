import hashlib


class EngineError(RuntimeError):
    """The engine could not run. The message says what to fix."""


class Engine:
    """Adapter contract.

    `replays` is False for adapters that import alerts produced elsewhere;
    the runner then calls `findings()` once instead of `run()` per capture.
    """

    name = 'engine'
    replays = True

    def describe(self):
        """Version, configuration and rule hashes, for the run manifest."""
        return {'name': self.name}

    def run(self, capture, paths, workdir):
        """Yield normalized findings for one capture (a list of files)."""
        raise NotImplementedError

    def findings(self, pack):
        raise NotImplementedError


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as fh:
        for block in iter(lambda: fh.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()
