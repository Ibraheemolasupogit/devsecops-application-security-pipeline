import subprocess


def run() -> None:
    subprocess.run(["python", "--version"], check=True)
