from __future__ import annotations

import json
from importlib.resources import files
from typing import Any


def load_data(filename: str) -> dict[str, Any]:
    resource = files("osint_toolbox").joinpath("data", filename)
    return json.loads(resource.read_text(encoding="utf-8"))


def find_tools(topic: str | None = None, search: str | None = None) -> list[dict[str, Any]]:
    tools = load_data("tools.json")["tools"]
    if topic:
        topic_value = topic.lower()
        tools = [tool for tool in tools if topic_value in [item.lower() for item in tool["topics"]]]
    if search:
        needle = search.lower()
        tools = [
            tool
            for tool in tools
            if needle in " ".join(
                [tool["id"], tool["name"], tool["role"], tool["notes"], " ".join(tool["topics"])]
            ).lower()
        ]
    return tools


def load_workflows() -> dict[str, Any]:
    return load_data("workflows.json")

