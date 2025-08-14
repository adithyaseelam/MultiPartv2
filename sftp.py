#!/usr/bin/env python3
import os
import sys
import socket
import logging
from logging.handlers import RotatingFileHandler
import paramiko
import hvac
import io
from base64 import b64decode
import configparser

def load_config(path: str) -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config.read(path)
    return config

def setup_logger(cfg):
    log_file = cfg.get("logging", "logfile")
    level = getattr(logging, cfg.get("logging", "level", fallback="INFO").upper())
    max_bytes = cfg.getint("logging", "max_bytes", fallback=1048576)
    backups = cfg.getint("logging", "backups", fallback=5)
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
    if role_id and secret_id:
        client.auth.approle.login(role_id=role_id, secret_id=secret_id)
    elif not client.is_authenticated():
        raise RuntimeError("Vault auth failed: supply VAULT_TOKEN or AppRole env vars")
    return client

def read_secret(client, path: str):
    if "/data/" in path:  # KV v2
        resp = client.secrets.kv.v2.read_secret_version(
            path=path.split("/data/")[1],
            mount_point=path.split("/data/")[0]
        )
        return resp["data"]["data"]
    else:  # KV v1
        resp = client.secrets.kv.v1.read_secret(path)
        return resp["data"]

def try_sftp_connect(host: str, port: int, username: str, password: str, pkey, timeout: int, logger) -> bool:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        logger.info(f"Attempting SFTP login to {host}:{port} as {username}")
        client.connect(
            hostname=host, port=port, username=username, password=password, pkey=pkey,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            look_for_keys=False, allow_agent=False
        )
        sftp = client.open_sftp()
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
    cfg_path = os.environ.get("SFTP_HEALTHCHECK_CONFIG", "config.ini")
    cfg = load_config(cfg_path)
    logger = setup_logger(cfg)

    host = cfg.get("sftp", "host")
    port = cfg.getint("sftp", "port", fallback=22)
    timeout = cfg.getint("logging", "timeout_seconds", fallback=10)

    client = get_vault_client()
    secret = read_secret(client, cfg.get("vault", "secret_path"))

    username_field = cfg.get("vault", "username_field", fallback="username")
    password_field = cfg.get("vault", "password_field", fallback="password")
    private_key_field = cfg.get("vault", "private_key_field", fallback=None)
    passphrase_field = cfg.get("vault", "passphrase_field", fallback=None)

    username = secret.get(username_field)
    password = secret.get(password_field)
    pkey = None

    if not username:
        logger.error(f"Vault secret missing '{username_field}'")
        sys.exit(2)

    if private_key_field and secret.get(private_key_field):
        key_data = secret[private_key_field]
        try:
            decoded = b64decode(key_data)
            key_str = decoded.decode()
        except Exception:
            key_str = key_data
        try:
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(key_str), password=secret.get(passphrase_field))
            password = None
        except Exception as e:
            logger.error(f"Failed to load private key: {e}")
            sys.exit(3)

    ok = try_sftp_connect(host, port, username, password, pkey, timeout, logger)
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()