#!/usr/bin/env python3
"""Repository-local direct-argv entry point for `harness-bundlectl verify`."""

from planeon_distribution.cli import main


if __name__ == "__main__":
    raise SystemExit(main(["verify", *__import__("sys").argv[1:]]))
