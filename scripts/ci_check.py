import subprocess
import sys


def run_step(name: str, cmd: list[str]) -> None:
    print(f"\n==> {name}")
    print(" ".join(cmd))
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def main() -> None:
    run_step("Run unit tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"])
    run_step("Check migration drift", [sys.executable, "-m", "flask", "--app", "app", "db", "check"])
    print("\nAll checks passed.")


if __name__ == "__main__":
    main()
