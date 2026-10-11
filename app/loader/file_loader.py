def preprocess_log_line(line: str) -> str:
    """Preserve the batch loader's edge-whitespace handling for all sources."""
    return line.strip()


def load_log_lines(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = preprocess_log_line(line)

            if line:
                yield line
