
import argparse
import sys

from secret_guard.main import SecretGuard


def main():
    parser = argparse.ArgumentParser(
        description="Secret Guard - Scan a file or directory"
    )

    parser.add_argument(
        "target",
        help="Đường dẫn file hoặc thư mục cần quét."
    )

    args = parser.parse_args()

    try:
        guard = SecretGuard()
        exit_code = guard.run(args.target)
        sys.exit(exit_code)

    except (
        FileNotFoundError,
        ValueError,
        TypeError,
        RuntimeError,
    ) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
