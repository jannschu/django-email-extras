from __future__ import unicode_literals

import re
from time import time

from django.core.exceptions import ValidationError
from django.contrib import messages
from django.db import models
from django.utils.encoding import python_2_unicode_compatible
from django.utils.translation import ugettext_lazy as _

from email_extras.gpg import GPG, constants, clean_key


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
        try:
            self.key = clean_key(self.key)
        except UnicodeDecodeError:
            raise ValidationError(_("Key is not valid ASCII"))
        with GPG(temporary=True) as gpg:
            gpg.op_import(self.key.encode())
            result = gpg.op_import_result()

        if result.considered == 0:
            raise ValidationError(_("No key was found"))
        if result.considered > 1:
            raise ValidationError(_("Includes more than one key"))

        fpr = result.imports[0].fpr
        key = gpg.get_key(fpr)

        if key.revoked:
            raise ValidationError(_("The key is revoked"))
        if key.expired:
            raise ValidationError(_("The key is expired"))
        if key.invalid or not key.can_encrypt:
            raise ValidationError(_("The key is invalid"))

    @classmethod
    def read_addresses(cls, key_data):
        with GPG(temporary=True) as gpg:
            gpg.op_import(clean_key(key_data).encode())
            result = gpg.op_import_result()
            if result.considered == 1:
                key = gpg.get_key(result.imports[0].fpr)
                return set(uid.email for uid in key.uids)
            else:
                return None

    def save(self, *args, **kwargs):
        with GPG() as gpg:
            key = self.key if isinstance(self.key, bytes) else str(self.key).encode()
            gpg.op_import(key)
            result = gpg.op_import_result()
            self.fingerprint = result.imports[0].fpr
            key = gpg.get_key(self.fingerprint)

        addresses = set(uid.email for uid in key.uids)

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
        with GPG() as gpg:
            gpg.op_delete_ext(
                gpg.get_key(self.fingerprint),
                constants.DELETE_ALLOW_SECRET | constants.DELETE_FORCE)


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
