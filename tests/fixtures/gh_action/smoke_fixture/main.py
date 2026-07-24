"""Smoke entry-point for the REQ-8 GitHub Action workflow.

Exercises Scarno's classification:
  * ``requests`` + ``click`` — IN_USE (imported below)
  * ``rich`` — SAFE (declared but not imported anywhere)
"""
from __future__ import annotations

import click
import requests


@click.command()
@click.option("--url", default="https://example.com")
def fetch(url: str) -> None:
    resp = requests.get(url, timeout=5)
    click.echo(f"{resp.status_code}: {len(resp.text)} bytes")


if __name__ == "__main__":
    fetch()
