"""Dataset loading script fixture (executes only if a user opts in)."""
import json


def load():
    with open("data.json", encoding="utf-8") as handle:
        return json.load(handle)
