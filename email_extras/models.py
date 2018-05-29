
from __future__ import unicode_literals

import re
from time import time

from django.core.exceptions import ValidationError
from django.contrib import messages
from django.db import models
from django.utils.encoding import python_2_unicode_compatible
from django.utils.translation import ugettext_lazy as _

from email_extras.settings import USE_GNUPG, GNUPG_HOME
from email_extras.utils import addresses_for_key, clean_key


if USE_GNUPG:
    from gnupg import GPG

    @python_2_unicode_compatible
    class Key(models.Model):
        """
        Accepts a key and imports it via admin's save_model which
        omits saving.
        """

        class Meta:
            verbose_name = _("Key")
            verbose_name_plural = _("Keys")

        key = models.TextField()
        fingerprint = models.CharField(max_length=200, editable=False,
            blank=True, unique=True, null=True)
        use_asc = models.BooleanField(default=False, help_text=_(
            "If True, an '.asc' extension will be added to email attachments "
            "sent to the address for this key."))

        def __str__(self):
            addresses = ", ".join(address.address for address in self.address_set.all())
            if addresses:
                return "PGP-Key {} ({})".format(self.fingerprint[:8], addresses)
            else:
                return "PGP-Key {}".format(self.fingerprint[:8])

        @property
        def email_addresses(self):
            return ",".join(str(address) for address in self.address_set.all())

        def clean(self, request=None):
            """
            Validates the key.

            If request is given warnings may be added using Django's messages
            framework.
            """
            super().clean()
            self.key = clean_key(self.key)
            gpg = GPG()
            result = gpg.import_keys(self.key)

            if result.count == 0:
                raise ValidationError(_("No key was found"))
            if result.count > 1:
                raise ValidationError(_("More than one key was imported"))
            if result.n_revoc > 0:
                raise ValidationError(_("The key is revoked"))

            assert len(result.fingerprints) == 1
            fp = result.fingerprints[0]
            key_data = next(k for k in gpg.list_keys() if k["fingerprint"] == fp)
            if 'expires' in key_data and re.match(r'^0|[1-9]\d*', key_data['expires']):
                if int(key_data['expires']) < time():
                    raise ValidationError(_("The key is expired"))

            if request is not None:
                problems = [(result.problem_reason[key['problem']], key.get('text'))
                            for key in result.results if 'problem' in key]
                if problems:
                    problem_text = _("There are problems with the PGP key: ") + \
                        ".".join(_(text or reason) for reason, text in problems) + \
                        "."
                    messages.warning(request, problem_text)

        @classmethod
        def read_addresses(cls, key_data):
            gpg = GPG()
            result = gpg.import_keys(clean_key(key_data))
            if result.count == 1 and result.n_revoc == 0:
                addresses = set()
                for key in result.results:
                    addresses.update(addresses_for_key(gpg, key))
                return addresses
            else:
                return None

        def save(self, *args, **kwargs):
            gpg = GPG(gnupghome=GNUPG_HOME)
            result = gpg.import_keys(self.key)

            addresses = set()
            for key in result.results:
                addresses.update(addresses_for_key(gpg, key))

            self.fingerprint = result.fingerprints[0]

            super(Key, self).save(*args, **kwargs)

            old_addresses = set(address.pk for address in self.address_set.all())

            for address in addresses:
                address, _ = Address.objects.get_or_create(key=self, address=address)
                address.use_asc = self.use_asc
                address.save()
                old_addresses.discard(address.pk)

            for address_pk in old_addresses:
                Address.objects.get(pk=address_pk).delete()

        def delete(self):
            super().delete()
            gpg = GPG(gnupghome=GNUPG_HOME)
            gpg.delete_keys([self.fingerprint])            


    @python_2_unicode_compatible
    class Address(models.Model):
        """
        Stores the address for a successfully imported key and allows
        deletion.
        """

        class Meta:
            verbose_name = _("Address")
            verbose_name_plural = _("Addresses")

        address = models.EmailField(blank=True)
        key = models.ForeignKey('email_extras.Key', null=True, editable=False)
        use_asc = models.BooleanField(default=False, editable=False)

        def __str__(self):
            return self.address
