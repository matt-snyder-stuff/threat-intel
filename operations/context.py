#!/usr/bin/env python3
"""Environment profile loading and organization-specific relevance scoring."""

import json
import os


PROFILE_CATEGORIES = {"labels", "vendors", "threat_actors", "keywords"}
TLP_ORDER = {"TLP:CLEAR": 0, "TLP:GREEN": 1, "TLP:AMBER": 2, "TLP:AMBER+STRICT": 3, "TLP:RED": 4}


def load_environment_profile(path):
    if not path:
        return {"name": "Generic environment", "priorities": {}}
    with open(path) as handle:
        profile = json.load(handle)
    if not isinstance(profile.get("name"), str) or not profile["name"].strip():
        raise ValueError("environment profile requires a non-empty name")
    priorities = profile.get("priorities", {})
    unknown = set(priorities) - PROFILE_CATEGORIES
    if unknown:
        raise ValueError(f"unknown environment profile categories: {', '.join(sorted(unknown))}")
    for category, values in priorities.items():
        if not isinstance(values, dict):
            raise ValueError(f"environment profile {category} must be an object")
        for value, weight in values.items():
            if not isinstance(value, str) or not isinstance(weight, int) or not 1 <= weight <= 100:
                raise ValueError(f"environment profile {category} weights must be integers from 1 through 100")
    return profile


def relevance_for_item(item, profile):
    priorities = profile.get("priorities", {})
    candidates = {
        "labels": item.get("all_labels", []),
        "vendors": item.get("t1_vendors", []) + item.get("t2_vendors", []),
        "threat_actors": item.get("tas", []),
    }
    score = 0
    matches = []
    for category, values in candidates.items():
        configured = priorities.get(category, {})
        for value in values:
            for target, weight in configured.items():
                if value.lower() == target.lower():
                    score += weight
                    matches.append(f"{category}:{target}")
    text = f"{item.get('name', '')} {item.get('description', '')}".lower()
    for keyword, weight in priorities.get("keywords", {}).items():
        if keyword.lower() in text:
            score += weight
            matches.append(f"keywords:{keyword}")
    return min(score, 100), sorted(set(matches))


def configured_profile_from_environment():
    path = os.environ.get("ENVIRONMENT_PROFILE", "")
    return load_environment_profile(path), bool(path), path


def filter_by_tlp(items, maximum_tlp):
    maximum_tlp = maximum_tlp.upper()
    if maximum_tlp not in TLP_ORDER:
        raise ValueError(f"invalid PUBLISH_MAX_TLP: {maximum_tlp}")
    included = []
    for item in items:
        item_tlp = item.get("tlp", "")
        if item_tlp not in TLP_ORDER:
            raise ValueError(f"invalid item TLP marking: {item_tlp}")
        if TLP_ORDER[item_tlp] <= TLP_ORDER[maximum_tlp]:
            included.append(item)
    return included, len(items) - len(included)
