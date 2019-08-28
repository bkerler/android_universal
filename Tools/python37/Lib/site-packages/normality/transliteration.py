# coding: utf-8
"""
Transliterate the given text to the latin script.

This attempts to convert a given text to latin script using the
closest match of characters vis a vis the original script.

Transliteration requires an extensive unicode mapping. Since all
Python implementations are either GPL-licensed (and thus more
restrictive than this library) or come with a massive C code
dependency, this module requires neither but will use a package
if it is installed.
"""
import six
from warnings import warn

try:
    # try to use pyicu (i.e. ICU4C)
    from icu import Transliterator

    def _latinize_internal(text, ascii=False):
        if ascii:
            if not hasattr(latinize_text, '_ascii'):
                # Transform to latin, separate accents, decompose, remove
                # symbols, compose, push to ASCII
                latinize_text._ascii = Transliterator.createInstance('Any-Latin; NFKD; [:Symbol:] Remove; [:Nonspacing Mark:] Remove; NFKC; Accents-Any; Latin-ASCII')  # noqa
            return latinize_text._ascii.transliterate(text)

        if not hasattr(latinize_text, '_tr'):
            latinize_text._tr = Transliterator.createInstance('Any-Latin')
        return latinize_text._tr.transliterate(text)

except ImportError:
    try:
        # try to use text_unidecode or unidecode (all Python, hence a bit
        # slower and less precise than the ICU version)
        try:
            from text_unidecode import unidecode

            def _latinize_internal(text, ascii=False):
                # weirdly, schwa becomes an @ by default in text_unidecode
                text = text.replace(u'ə', 'a')
                text = text.replace(u'Ə', 'A')
                return six.text_type(unidecode(text))
        except ImportError:
            from unidecode import unidecode

            def _latinize_internal(text, ascii=False):
                # weirdly, schwa becomes an @ by default in unidecode
                text = text.replace(u'ə', 'a')
                return six.text_type(unidecode(text))

    except ImportError:

        def _latinize_internal(text, ascii=False):
            warn("No transliteration library is available. Install 'pyicu' or 'text_unidecode' or 'unidecode'.", UnicodeWarning)  # noqa
            return text


def latinize_text(text, ascii=False):
    """Transliterate the given text to the latin script.

    This attempts to convert a given text to latin script using the
    closest match of characters vis a vis the original script.
    """
    if text is None or not isinstance(text, six.string_types) or not len(text):
        return text
    return _latinize_internal(text, ascii=ascii)


def ascii_text(text):
    """Transliterate the given text and make sure it ends up as ASCII."""
    text = latinize_text(text, ascii=True)
    if isinstance(text, six.text_type):
        text = text.encode('ascii', 'ignore').decode('ascii')
    return text
