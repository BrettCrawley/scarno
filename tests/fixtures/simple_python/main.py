"""Smoke-test fixture: requests is used, boto3 is not."""
import requests


def fetch(url: str) -> str:
    return requests.get(url).text
