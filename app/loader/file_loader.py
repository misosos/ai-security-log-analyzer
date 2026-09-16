def load_log_lines(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if line:
                yield line