from django import forms
from django.utils.translation import ugettext_lazy as _

from email_extras.gpg import GPG


class KeyForm(forms.ModelForm):

    def clean_key(self):
        """
        Validate the key contains an email address.
        """
        key = self.cleaned_data["key"]
        with GPG(temporary=True) as gpg:
            gpg.op_import(key.encode())
            result = gpg.op_import_result()
        if result.considered == 0:
            raise forms.ValidationError(_("Invalid Key"))
        return key
