__version__ = "0.3.3"
default_app_config = 'email_extras.apps.EmailExtrasConfig'

try:
    from pretty_bad_protocol._parser import ListKeys
    # See https://github.com/isislovecruft/python-gnupg/issues/225
    def _fix_fpr(self, args):
        if 'fingerprint' not in self.curkey:
            self.curkey['fingerprint'] = args[9]
            self.fingerprints.append(args[9])
    ListKeys.fpr = _fix_fpr
except:
    pass
