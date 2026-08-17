"""``regent-httpsig keygen`` — generate an agent key + ready-to-publish directory."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from regent_httpsig.sign import EgressSigner, generate_seed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="regent-httpsig",
        description="Utilities for RFC 9421 agent signatures (Web Bot Auth / AAuth).",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser(
        "keygen",
        help="Generate an Ed25519 agent key and the well-known directory files.",
    )
    keygen.add_argument(
        "--agent", default="https://myagent.example",
        help="Your agent's origin (where you will host the key directory).",
    )
    keygen.add_argument(
        "--out", type=Path, default=None,
        help="Directory to write http-message-signatures-directory + jwks.json into.",
    )
    args = parser.parse_args(argv)

    if args.command == "keygen":
        seed = generate_seed()
        signer = EgressSigner(seed=seed, signature_agent=args.agent)
        directory = json.dumps(signer.directory(), indent=2)
        print("# Keep this secret — it IS your agent's identity:", file=sys.stderr)
        print(f"AGENT_KEY_SEED={seed}")
        print(f"# keyid (RFC 7638 thumbprint): {signer.keyid}", file=sys.stderr)
        if args.out:
            args.out.mkdir(parents=True, exist_ok=True)
            (args.out / "http-message-signatures-directory").write_text(directory)
            (args.out / "jwks.json").write_text(directory)
            print(
                f"# Wrote {args.out}/http-message-signatures-directory and jwks.json\n"
                f"# Serve them at {args.agent}/.well-known/",
                file=sys.stderr,
            )
        else:
            print(directory, file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
