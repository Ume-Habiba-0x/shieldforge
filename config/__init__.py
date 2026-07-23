from pathlib import Path

CONFIG_DIR = Path(__file__).parent
PAYLOADS_DIR = CONFIG_DIR / "payloads"


def load_payloads(filename: str) -> list[str]:
    """Read a payload file and return non-empty, non-comment lines.

    Args:
        filename: Filename inside config/payloads/.

    Returns:
        List of payload strings.

    Raises:
        FileNotFoundError: If the payload file does not exist.
    """
    path = PAYLOADS_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Payload file not found: {path}")

    payloads = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                payloads.append(line)

    return payloads