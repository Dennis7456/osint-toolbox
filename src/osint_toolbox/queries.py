from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote_plus

from .catalog import load_data


ENGINE_URLS = {
    "google": "https://www.google.com/search?q={query}",
    "bing": "https://www.bing.com/search?q={query}",
    "brave": "https://search.brave.com/search?q={query}",
    "duckduckgo": "https://duckduckgo.com/?q={query}",
}


def list_recipes() -> list[dict[str, Any]]:
    return load_data("query_recipes.json")["recipes"]


def get_recipe(recipe_id: str) -> dict[str, Any]:
    for recipe in list_recipes():
        if recipe["id"] == recipe_id:
            return recipe
    raise ValueError(f"Unknown recipe: {recipe_id}")


def build_query(recipe_id: str, parameters: dict[str, str], engine: str) -> tuple[str, str]:
    recipe = get_recipe(recipe_id)
    required = set(re.findall(r"{([a-zA-Z0-9_]+)}", recipe["template"]))
    missing = sorted(required - set(parameters))
    if missing:
        raise ValueError(f"Missing parameters: {', '.join(missing)}")
    query = recipe["template"].format(**parameters)
    if engine not in ENGINE_URLS:
        raise ValueError(f"Unknown engine: {engine}")
    return query, ENGINE_URLS[engine].format(query=quote_plus(query))

