#!/usr/bin/env python3
import os, sys, socket, logging, yaml
from logging.handlers import RotatingFileHandler
import paramiko
import hvac
from base64 import b64decode

def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)

def setup_logger(cfg):
    log_file = cfg["logging"]["logfile"]
    level = getattr(logging, cfg["logging"].get("level", "INFO"))
    max_bytes = int(cfg["logging"].get("max_bytes", 1048576))
    backups = int(cfg["logging"].get("backups", 5))
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backups)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(fmt)
    logger = logging.getLogger("sftp_healthcheck")
    logger.setLevel(level)
    logger.addHandler(handler)
    return logger

def get_vault_client():
    addr = os.getenv("VAULT_ADDR")
    token = os.getenv("VAULT_TOKEN")
    role_id = os.getenv("VAULT_ROLE_ID")
    secret_id = os.getenv("VAULT_SECRET_ID")
    if not addr:
        raise RuntimeError("VAULT_ADDR not set")
    client = hvac.Client(url=addr, token=token if token else None)
    # AppRole auth (preferred for automation) if provided
    if role_id and secret_id:
        client.auth.approle.login(role_id=role_id, secret_id=secret_id)
    elif not client.is_authenticated():
        raise RuntimeError("Vault auth failed: supply VAULT_TOKEN or AppRole env (VAULT_ROLE_ID/VAULT_SECRET_ID)")
    return client

def read_secret(client, path: str):
    """
    Supports KV v2 path like 'kv/data/...'.
    For KV v1, path may be 'kv/...', and return format differs.
    """
    if "/data/" in path:  # KV v2
        resp = client.secrets.kv.v2.read_secret_version(path=path.split("/data/")[1], mount_point=path.split("/data/")[0])
        return resp["data"]["data"]
    else:  # KV v1
        resp = client.secrets.kv.v1.read_secret(path)
        return resp["data"]

def build_auth(secret: dict, user_field: str, pass_field: str, key_field: str = None, passphrase_field: str = None):
    username = secret[user_field]
    password = secret.get(pass_field)
    pkey = None
    if key_field and secret.get(key_field):
        key_bytes = secret[key_field].encode()
        # Support base64-encoded or raw PEM
        try:
            key_bytes = b64decode(key_bytes)
        except Exception:
            pass
        pkey = paramiko.RSAKey.from_private_key(io.StringIO(key_bytes.decode()), password=secret.get(passphrase_field))
    return username, password, pkey

def try_sftp_connect(host: str, port: int, username: str, password: str, pkey, timeout: int, logger) -> bool:
    client = paramiko.SSHClient()
    # In monitoring, we usually don’t manage known_hosts; accept host key but log the fingerprint.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        logger.info(f"Attempting SFTP login to {host}:{port} as {username}")
        client.connect(
            hostname=host, port=port, username=username, password=password, pkey=pkey,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout, look_for_keys=False, allow_agent=False
        )
        sftp = client.open_sftp()
        # Lightweight op to validate the session
        sftp.listdir(".")
        sftp.close()
        logger.info("SFTP connectivity OK")
        return True
    except (paramiko.AuthenticationException, paramiko.SSHException) as e:
        logger.error(f"SFTP auth/SSH failure: {e}")
        return False
    except (socket.timeout, socket.error) as e:
        logger.error(f"Network error: {e}")
        return False
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return False
    finally:
        try:
            client.close()
        except Exception:
            pass

def main():
    cfg_path = os.environ.get("SFTP_HEALTHCHECK_CONFIG", "config.yaml")
    cfg = load_config(cfg_path)
    logger = setup_logger(cfg)

    host = cfg["sftp"]["host"]
    port = int(cfg["sftp"].get("port", 22))
    timeout = int(cfg["logging"].get("timeout_seconds", 10))

    # Vault
    client = get_vault_client()
    secret = read_secret(client, cfg["vault"]["secret_path"])

    username_field = cfg["vault"].get("username_field", "username")
    password_field = cfg["vault"].get("password_field", "password")
    private_key_field = cfg["vault"].get("private_key_field")  # optional
    passphrase_field = cfg["vault"].get("passphrase_field")    # optional

    username = secret.get(username_field)
    password = secret.get(password_field)
    pkey = None

    if not username:
        logger.error(f"Vault secret missing '{username_field}'")
        sys.exit(2)

    # Private key support (optional)
    if private_key_field and secret.get(private_key_field):
        import io
        key_data = secret[private_key_field]
        try:
            # Try base64-decoded first
            from base64 import b64decode
            decoded = b64decode(key_data)
            key_str = decoded.decode()
        except Exception:
            key_str = key_data
        try:
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(key_str), password=secret.get(passphrase_field))
            password = None  # prefer key auth
        except Exception as e:
            logger.error(f"Failed to load private key from Vault field '{private_key_field}': {e}")
            sys.exit(3)

    ok = try_sftp_connect(host, port, username, password, pkey, timeout, logger)
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()