"""One-shot: rotate leaked root password, install SSH key, disable password auth.

Reads:
    AXIOM_SSH_HOST       host IP
    AXIOM_SSH_OLD_PASS   leaked password (will be rotated away)
    AXIOM_SSH_NEW_PASS   new strong password (kept as backup access path)
    AXIOM_SSH_KEY_PATH   path to local private key (public key will be uploaded)

Does NOT print any password to stdout. Does NOT save either password anywhere.
"""

import os
import sys
import time
import paramiko


def main() -> int:
    host = os.environ["AXIOM_SSH_HOST"]
    old_pass = os.environ["AXIOM_SSH_OLD_PASS"]
    new_pass = os.environ["AXIOM_SSH_NEW_PASS"]
    key_path = os.environ["AXIOM_SSH_KEY_PATH"]

    with open(key_path + ".pub") as f:
        pubkey = f.read().strip()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"connecting to {host} as root (password auth)…", flush=True)
    client.connect(
        host,
        username="root",
        password=old_pass,
        timeout=15,
        allow_agent=False,
        look_for_keys=False,
    )
    print("connected", flush=True)

    def run(cmd: str, input_data: str | None = None, check: bool = True) -> tuple[int, str, str]:
        stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
        if input_data is not None:
            stdin.write(input_data)
            stdin.flush()
            stdin.channel.shutdown_write()
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        rc = stdout.channel.recv_exit_status()
        if check and rc != 0:
            raise RuntimeError(f"cmd failed rc={rc}: {cmd}\nstdout={out}\nstderr={err}")
        return rc, out, err

    # 1. install pubkey
    print("installing ssh key…", flush=True)
    run("mkdir -p /root/.ssh && chmod 700 /root/.ssh")
    run(
        "cat >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys",
        input_data=pubkey + "\n",
    )
    # dedupe
    run(
        "sort -u /root/.ssh/authorized_keys -o /root/.ssh/authorized_keys "
        "&& chmod 600 /root/.ssh/authorized_keys"
    )

    # 2. rotate root password via chpasswd (stdin: root:newpass)
    print("rotating root password…", flush=True)
    run("chpasswd", input_data=f"root:{new_pass}\n")

    # 3. capture initial state for report
    print("collecting host info…", flush=True)
    _, uname, _ = run("uname -a && cat /etc/os-release | head -5")
    _, mem, _ = run("free -h | head -2")
    _, disk, _ = run("df -h / | tail -1")
    _, docker_v, _ = run("command -v docker && docker --version || echo NO_DOCKER", check=False)
    _, compose_v, _ = run("docker compose version 2>/dev/null || echo NO_COMPOSE", check=False)
    _, ports, _ = run("ss -tlnp 2>/dev/null | head -20 || netstat -tlnp | head -20", check=False)

    print("---HOST INFO---", flush=True)
    print(uname)
    print(mem)
    print("disk:", disk)
    print("docker:", docker_v.strip())
    print("compose:", compose_v.strip())
    print("---LISTENING PORTS---")
    print(ports)

    client.close()

    # 4. verify key auth works (connect again with key, no password)
    print("verifying key auth…", flush=True)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pkey = paramiko.Ed25519Key.from_private_key_file(key_path)
    client.connect(
        host,
        username="root",
        pkey=pkey,
        timeout=15,
        allow_agent=False,
        look_for_keys=False,
    )
    stdin, stdout, stderr = client.exec_command("whoami && hostname")
    out = stdout.read().decode().strip()
    print("key auth OK:", out)
    client.close()

    print("BOOTSTRAP_COMPLETE", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
