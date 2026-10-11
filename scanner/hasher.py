import hashlib
from pathlib import Path


def calculate_sha256(file_path, chunk_size=1024 * 1024):
    """
    Calculate the SHA-256 hash of a file.

    Reads the file in chunks so large files do not need
    to be loaded entirely into memory.
    """

    file_path = Path(file_path)

    if not file_path.exists():
        return None

    if not file_path.is_file():
        return None

    sha256 = hashlib.sha256()

    try:

        with file_path.open("rb") as file:

            while True:

                chunk = file.read(chunk_size)

                if not chunk:
                    break

                sha256.update(chunk)

        return sha256.hexdigest()

    except OSError as e:

        print("HASH ERROR:", e)

        return None