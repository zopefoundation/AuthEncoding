def to_bytes(arg):
    """Convert `arg` to bytes."""
    if isinstance(arg, str):
        arg = arg.encode("latin-1")
    return arg


def to_string(arg):
    """Convert `arg` to text."""
    if isinstance(arg, bytes):
        arg = arg.decode('ascii', 'replace')
    return arg
