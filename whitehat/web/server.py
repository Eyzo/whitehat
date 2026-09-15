"""Lanceur du serveur web local."""

from __future__ import annotations

import argparse

import uvicorn


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="whitehat-web",
        description="Lance la console web whitehat en local.")
    p.add_argument("--host", default="127.0.0.1",
                   help="Adresse d'écoute (défaut: 127.0.0.1, local uniquement)")
    p.add_argument("--port", type=int, default=8787, help="Port (défaut: 8787)")
    p.add_argument("--reload", action="store_true", help="Rechargement auto (dev)")
    args = p.parse_args(argv)

    print(f"→ Console whitehat : http://{args.host}:{args.port}")
    print("  ⚠️  Usage autorisé uniquement. Ne scanne que des cibles pour lesquelles "
          "tu as l'autorisation.")
    uvicorn.run("whitehat.web.app:app", host=args.host, port=args.port,
                reload=args.reload, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
