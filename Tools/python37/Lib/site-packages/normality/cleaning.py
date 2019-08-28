# coding: utf-8
from __future__ import unicode_literals

import re
import six
from unicodedata import normalize, category

from normality.constants import UNICODE_CATEGORIES, CONTROL_CODES, WS

COLLAPSE_RE = re.compile(r'\s+', re.U)
BOM_RE = re.compile('^\ufeff', re.U)
UNSAFE_RE = re.compile('\x00', re.U)
QUOTES_RE = re.compile('^["\'](.*)["\']$')

try:
    # try to use pyicu (i.e. ICU4C)
    from icu import Transliterator

    def _decompose_nfkd(text):
        if not hasattr(_decompose_nfkd, '_tr'):
            _decompose_nfkd._tr = Transliterator.createInstance('Any-NFKD')
        return _decompose_nfkd._tr.transliterate(text)

    def _compose_nfc(text):
        if not hasattr(_compose_nfc, '_tr'):
            _compose_nfc._tr = Transliterator.createInstance('Any-NFC')
        return _compose_nfc._tr.transliterate(text)

except ImportError:

    def _decompose_nfkd(text):
        return normalize('NFKD', text)

    def _compose_nfc(text):
        return normalize('NFC', text)


def decompose_nfkd(text):
    """Perform unicode compatibility decomposition.

    This will replace some non-standard value representations in unicode and
    normalise them, while also separating characters and their diacritics into
    two separate codepoints.
    """
    if text is None:
        return None
    return _decompose_nfkd(text)


def compose_nfc(text):
    """Perform unicode composition."""
    if text is None:
        return None
    return _compose_nfc(text)


def strip_quotes(text):
    """Remove double or single quotes surrounding a string."""
    if text is None:
        return
    return QUOTES_RE.sub('\\1', text)


def category_replace(text, replacements=UNICODE_CATEGORIES):
    """Remove characters from a string based on unicode classes.

    This is a method for removing non-text characters (such as punctuation,
    whitespace, marks and diacritics) from a piece of text by class, rather
    than specifying them individually.
    """
    if text is None:
        return None
    characters = []
    for character in decompose_nfkd(text):
        cat = category(character)
        replacement = replacements.get(cat, character)
        if replacement is not None:
            characters.append(replacement)
    return u''.join(characters)


def remove_control_chars(text):
    """Remove just the control codes from a piece of text."""
    return category_replace(text, replacements=CONTROL_CODES)


def remove_unsafe_chars(text):
    """Remove unsafe unicode characters from a piece of text."""
    if isinstance(text, six.string_types):
        text = UNSAFE_RE.sub('', text)
    return text


def remove_byte_order_mark(text):
    """Remove a BOM from the beginning of the text."""
    return BOM_RE.sub('', text)


def collapse_spaces(text):
    """Remove newlines, tabs and multiple spaces with single spaces."""
    if not isinstance(text, six.string_types):
        return text
    return COLLAPSE_RE.sub(WS, text).strip(WS)
