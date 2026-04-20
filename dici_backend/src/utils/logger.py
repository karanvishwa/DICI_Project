import logging, os, yaml
from pathlib import Path

def load_config(config_path=None):
    if config_path is None:
        base = Path(__file__).resolve().parents[2]
        config_path = base / "config" / "config.yaml"
    with open(config_path) as f:
        return yaml.safe_load(f)

def get_logger(name, config_path=None):
    try:
        cfg = load_config(config_path)
        lc = cfg.get("logging", {})
        level_str = lc.get("level", "INFO")
        log_file  = lc.get("log_file", "dici.log")
        fmt       = lc.get("format", "%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    except Exception:
        level_str, log_file, fmt = "INFO", "dici.log", "%(asctime)s | %(levelname)s | %(name)s | %(message)s"

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(getattr(logging, level_str.upper(), logging.INFO))
    formatter = logging.Formatter(fmt)
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    try:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        fh = logging.FileHandler(log_file)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    except Exception:
        pass
    return logger
