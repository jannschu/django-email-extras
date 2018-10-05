from django import forms
from django.utils.translation import ugettext_lazy as _

from email_extras.settings import USE_GNUPG, GNUPG_HOME

if USE_GNUPG:
    from pretty_bad_protocol.gnupg import GPG


class KeyForm(forms.ModelForm):

    def clean_key(self):
        """
        Validate the key contains an email address.
        """
        key = self.cleaned_data["key"]
        gpg = GPG(homedir=GNUPG_HOME)
        result = gpg.import_keys(key)
        if result.counts['count'] == 0:
            raise forms.ValidationError(_("Invalid Key"))
        return key
