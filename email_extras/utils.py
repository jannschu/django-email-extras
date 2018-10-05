from __future__ import with_statement
from os.path import basename
from warnings import warn
import re

from email.mime.base import MIMEBase
from email import encoders

from django.template import loader
from django.core.mail import EmailMultiAlternatives, SafeMIMEText, SafeMIMEMultipart, get_connection
from django.utils import six
from django.utils.encoding import smart_text

from email_extras.settings import (USE_GNUPG, GNUPG_HOME, ALWAYS_TRUST,
                                   SIGN)


if USE_GNUPG:
    from pretty_bad_protocol.gnupg import GPG


class EncryptionFailedError(Exception):
    pass


def addresses_for_key(gpg, fingerprint):
    """
    Takes a key and extracts the email addresses for it.
    """
    addresses = []
    for key in gpg.list_keys():
        if key["fingerprint"] == fingerprint:
            addresses.extend([address.split("<")[-1].strip(">")
                              for address in key["uids"] if address])
    return addresses


def fingerprints_for_address(gpg, address):
    fps = []
    for key in gpg.list_keys():
        for uid in key["uids"]:
            if uid.split("<")[-1].strip(">") == address:
                fps.append(key["fingerprint"])
    return fps


RE_CLEAN_KEY = re.compile(
        "(" + 
            "|".join([re.escape(c) for c in r'''~!@#$%^&*()_+`-={}|[]\;':"<>?,./- ''']) +
        ")*(?=-----(?:BEGIN|END) PGP)")


def clean_key(key):
    # PGP does accept some additional characters which we need to
    # remove for GPG to accept the key
    return re.sub(RE_CLEAN_KEY, '', key.strip())


def send_mail(subject, body_text, addr_from, recipient_list,
              fail_silently=False, auth_user=None, auth_password=None,
              attachments=None, body_html=None, html_message=None,
              connection=None, headers=None):
    """
    Sends a multipart email containing text and html versions which
    are encrypted for each recipient that has a valid gpg key
    installed.
    """

    # Make sure only one HTML option is specified
    if body_html is not None and html_message is not None:  # pragma: no cover
        raise ValueError("You cannot specify body_html and html_message at "
                         "the same time. Please only use html_message.")

    # Push users to update their code
    if body_html is not None:  # pragma: no cover
        warn("Using body_html is deprecated; use the html_message argument "
             "instead. Please update your code.", DeprecationWarning)
        html_message = body_html

    # Allow for a single address to be passed in.
    if isinstance(recipient_list, six.string_types):
        recipient_list = [recipient_list]

    connection = connection or get_connection(
        username=auth_user, password=auth_password,
        fail_silently=fail_silently)

    # Obtain a list of the recipients that have gpg keys installed.
    key_addresses = {}
    gpg = None
    if USE_GNUPG:
        from email_extras.models import Address
        key_addresses = dict(Address.objects.filter(address__in=recipient_list)
                                            .values_list('address', 'use_asc'))
        # Create the gpg object.
        if key_addresses:
            gpg = GPG(homedir=GNUPG_HOME)

    # Load attachments and create name/data tuples.
    attachments_parts = []
    if attachments is not None:
        for attachment in attachments:
            # Attachments can be pairs of name/data, or filesystem paths.
            if not hasattr(attachment, "__iter__"):
                with open(attachment, "rb") as f:
                    attachments_parts.append((basename(attachment), f.read()))
            else:
                attachments_parts.append(attachment)

    # Send emails - encrypted emails needs to be sent individually, while
    # non-encrypted emails can be sent in one send. So the final list of
    # lists of addresses to send to looks like:
    # [[unencrypted1, unencrypted2, unencrypted3], [encrypted1], [encrypted2]]
    unencrypted = [addr for addr in recipient_list
                   if addr not in key_addresses]
    unencrypted = [unencrypted] if unencrypted else unencrypted
    encrypted = [[addr] for addr in key_addresses]
    for addr_list in unencrypted + encrypted:
        msg = PGPEmailMultiAlternatives(subject,
                                        body_text,
                                        addr_from, addr_list,
                                        connection=connection,
                                        headers=headers,
                                        gpg=gpg,
                                        fail_silently=fail_silently,
                                        encrypt=addr_list[0] in key_addresses)
        if html_message is not None:
            msg.attach_alternative("text/html")
        for parts in attachments_parts:
            msg.attach(*parts)
        msg.send(fail_silently=fail_silently)


def send_mail_template(subject, template, addr_from, recipient_list,
                       fail_silently=False, attachments=None, context=None,
                       connection=None, headers=None):
    """
    Send email rendering text and html versions for the specified
    template name using the context dictionary passed in.
    """

    if context is None:
        context = {}

    # Loads a template passing in vars as context.
    def render(ext):
        name = "email_extras/%s.%s" % (template, ext)
        return loader.get_template(name).render(context)

    send_mail(subject, render("txt"), addr_from, recipient_list,
              fail_silently=fail_silently, attachments=attachments,
              html_message=render("html"), connection=connection,
              headers=headers)


class PGPEmailMultiAlternatives(EmailMultiAlternatives):
    def __init__(self, *args, **kwargs):
        self.gpg = kwargs.pop('gpg')
        self.encrypt = kwargs.pop('encrypt', False)
        self.fail_silently = kwargs.pop('fail_silently')
        super().__init__(*args, **kwargs)

    def attach(self, filename=None, content=None, mimetype=None):
        if isinstance(self.body, str) and not re.search(r'\r?\n[ \t\r]*\r?\n\s*\Z', self.body):
            self.body += '\n\n'
        super().attach(filename, content, mimetype)

    def _create_mime_attachment(self, content, mimetype):
        basetype, subtype = mimetype.split('/', 1)
        if basetype == "text":
            attachment = MIMEBase(basetype, subtype)
            attachment.set_payload(content)
            encoders.encode_quopri(attachment)
            return attachment
        else:
            return super()._create_mime_attachment(content, mimetype)

    def _create_message(self, msg):
        msg = super()._create_message(msg)
        if self.gpg is None:
            return msg
        if SIGN:
            sign_msg = msg
            sign_text = re.sub('\r?\n', '\r\n', sign_msg.as_string())
            if sign_msg.is_multipart() and not sign_text.endswith("\r\n"):
                sign_text += "\r\n"
            signature = self.gpg.sign(
                sign_text,
                detach=True, clearsign=False,
                digest_algo='SHA512')
            if signature:
                msg = SafeMIMEMultipart(
                    _subtype="signed",
                    protocol="application/pgp-signature",
                    mictype="pgp-sha512")
                msg.attach(sign_msg)
                sig = MIMEBase('application', 'pgp-signature', name='signature.asc')
                sig.add_header('Content-Disposition', 'attachment', filename='signature.asc')
                sig.add_header('Content-Description', 'Message signed with OpenPGP', filename='signature.asc')
                sig.set_payload(signature.data, 'ascii')
                msg.attach(sig)
            elif not self.fail_silently:
                raise ValueError("PGP signing failed")
        if self.encrypt:
            encrypted = self.gpg.encrypt(
                msg.as_string(), 
                *fingerprints_for_address(self.gpg, self.to[0]))
            if encrypted:
                msg = SafeMIMEMultipart(
                    _subtype="encrypted",
                    protocol="application/pgp-encrypted")
                description = MIMEBase('application', 'pgp-encrypted')
                description.set_payload('Version: 1', 'ascii')
                description.add_header('Content-Description', 'PGP/MIME Versions Identification')
                msg.attach(description)
                body = MIMEBase('application', 'octet-stream', name='encrypted.asc')
                body.add_header('Content-Disposition', 'inline', filename='encrypted.asc')
                body.add_header('Content-Description', 'OpenPGP encrypted message')
                body.set_payload(encrypted.data, 'ascii')
                msg.attach(body)
                msg.preamble = "This is an OpenPGP/MIME encrypted message (RFC 2400 and 3156)"
            elif not self.fail_silently:
                raise ValueError("PGP encryption failed")
        return msg


    # Encrypts body if recipient has a gpg key installed.
    def encrypt_if_key(body, addr_list):
        if has_pgp_key(addr_list[0]):
            encrypted = gpg.encrypt(body, addr_list[0],
                                    always_trust=ALWAYS_TRUST, sign=SIGN)
            if encrypted == "" and body != "":  # encryption failed
                raise EncryptionFailedError("Encrypting mail to %s failed.",
                                            addr_list[0])
            return smart_text(encrypted)
        return body

