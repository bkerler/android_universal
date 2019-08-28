from collections import Mapping

from banal.lists import is_sequence


def is_mapping(obj):
    return isinstance(obj, Mapping)


def clean_dict(data):
    """Remove None-valued keys from a dictionary, recursively."""
    if is_mapping(data):
        out = {}
        for k, v in data.items():
            if v is not None:
                out[k] = clean_dict(v)
        return out
    elif is_sequence(data):
        return [clean_dict(d) for d in data if d is not None]
    return data
