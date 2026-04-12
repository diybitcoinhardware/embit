import uembit as _uembit

from .base import WordlistBase as _WordlistBase

WORDLIST = _WordlistBase(_uembit.wordlists.bip39)
