import sys
from ipaddress import ip_address

from pkg_resources import resource_filename

from .file_helper import get_combined_word_lists

DEFAULT_WORDLIST_FILE = resource_filename(
    'VHostScan', 'wordlists/virtual-host-scanning.txt')


class WordList:
    def __init__(self):
        self.wordlist = []
        self.wordlist_types = []

    def get_stdin_wordlist(self):
        return [] if sys.stdin.isatty() else list(sys.stdin.read().splitlines())

    def get_wordlist(self,
                     wordlist_files=None,
                     wordlist_prefix=False,
                     wordlist_suffix=False):

        default_wordlist_file = DEFAULT_WORDLIST_FILE

        if stdin_words := self.get_stdin_wordlist():
            self.set_words(words_type='stdin', words=stdin_words)
            default_wordlist_file = None

        combined_files = wordlist_files or default_wordlist_file
        if combined := get_combined_word_lists(combined_files):
            words_type = f"wordlists: {', '.join(combined['file_paths'])}"
            self.set_words(words_type=words_type, words=combined['words'])

        # Apply prefixes
        if wordlist_prefix:
            if prefixed := [
                wordlist_prefix + word
                for word in self.wordlist
                if word != '%s' and (word == '%s' or not (self.valid_ip(word)))
            ]:
                self.wordlist = self.wordlist + prefixed

        if wordlist_suffix:
            suffixed = []
            for word in self.wordlist:
                if (word == '%s') or word != '%s' and (self.valid_ip(word)):
                    continue
                elif word != '%s' and not (self.valid_ip(word)) and ".%s" in word:
                    split = word.split(".")
                    suffixed.append(split[0] + wordlist_suffix + ".%s")
                else:
                    suffixed.append(word + wordlist_suffix)

            if suffixed:
                self.wordlist = self.wordlist + suffixed

        return self.wordlist, self.wordlist_types

    def set_words(self, words_type, words):
        self.wordlist_types.append(words_type)
        self.wordlist.extend(words)

    def valid_ip(self, address):
        try:
            return ip_address(address) is not None
        except:
            return False
