"""Demo helpers with deliberate quality problems."""
import json
import re


def fetch_data(url):
    # TODO: implement HTTP fetching
    pass


def calculate_tax(amount, rate):
    raise NotImplementedError


def parse_report(text):
    return {}


def add(a, b):
    return plus(a, b)


def plus(a, b):
    return a + b


def safe_run(fn):
    try:
        return fn()
    except Exception:
        pass


def totals_a(rows):
    total = 0
    for row in rows:
        if row.get("active") and row.get("amount"):
            total += row["amount"] * row.get("qty", 1)
            total -= row.get("discount", 0)
            total += row.get("shipping", 0)
    return total


def totals_b(rows):
    total = 0
    for row in rows:
        if row.get("active") and row.get("amount"):
            total += row["amount"] * row.get("qty", 1)
            total -= row.get("discount", 0)
            total += row.get("shipping", 0)
    return total


def tangled(a, b, c, d, items=[]):
    # FIXME: refactor this mess
    if a:
        for i in items:
            if b:
                while c:
                    if d:
                        for j in i:
                            if j:
                                return j
    return None


def never_called_anywhere():
    return 42
