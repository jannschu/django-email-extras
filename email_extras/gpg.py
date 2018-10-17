from tempfile import mkdtemp
from shutil import rmtree
import re

import gpg as gpgme
import gpg.constants as constants

from email_extras.settings import GNUPG_HOME

DEFAULTS = {
    'pinentry_mode': constants.PINENTRY_MODE_ERROR,
    'armor': True,
}

class TemporaryGPG:
    def __init__(self, **kwargs):
        self._dir = mkdtemp()
        options = DEFAULTS.copy()
        options.update(kwargs)
        options['home_dir'] = self._dir
        self._gpg = gpgme.Context(options)

    def __enter__(self):
        return self._gpg

    def __exit__(self, exc_type, exc_val, exc_tb):
        del self._gpg
        rmtree(self._dir)


def GPG(**kwargs):
    options = DEFAULTS.copy()
    options.update(kwargs)
    if kwargs.pop('temporary', False):
        return TemporaryGPG(**options)
    else:
        options['home_dir'] = GNUPG_HOME
        return gpgme.Context(**options)


RE_CLEAN_KEY = re.compile(
        "(" + 
            "|".join([re.escape(c) for c in r'''~!@#$%^&*()_+`-={}|[]\;':"<>?,./- ''']) +
        ")*(?=-----(?:BEGIN|END) PGP)")


def clean_key(key):
    # PGP does accept some additional characters which we need to
    # remove for GPG to accept the key
    if isinstance(key, bytes):
        key = key.decode('ascii')
    return re.sub(RE_CLEAN_KEY, '', str(key).strip())


HASH_ALGORITHM = {}
for md in dir(constants.md):
    if md.startswith('__'):
        continue
    hash_nr = getattr(constants.md, md)
    HASH_ALGORITHM[hash_nr] = md.lower().replace('_', '-')

