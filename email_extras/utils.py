from __future__ import with_statement
from os.path import basename
from warnings import warn
import re

from email.mime.base import MIMEBase
from email import encoders, charset as emailcharset

from django.template import loader
from django.core.mail import EmailMultiAlternatives, SafeMIMEText, SafeMIMEMultipart, get_connection
from django.utils import six
from django.utils.encoding import smart_text
from django.conf import settings

from email_extras.settings import GNUPG_HOME, ALWAYS_TRUST, SIGN
from email_extras.gpg import GPG, constants, HASH_ALGORITHM
from email_extras.models import Address


# See https://code.djangoproject.com/ticket/29830
def _29830_set_payload(self, payload, charset=None):
    from django.core.mail.message import utf8_charset_qp, utf8_charset, RFC5322_EMAIL_LINE_LENGTH_LIMIT
    from email.mime.text import MIMEText
    if charset == 'utf-8' and not isinstance(charset, emailcharset.Charset):
        has_long_lines = any(
            len(l.encode('utf-8')) > RFC5322_EMAIL_LINE_LENGTH_LIMIT
            for l in payload.splitlines()
        )
        # Quoted-Printable encoding has the side effect of shortening long
        # lines, if any (#22561).
        charset = utf8_charset_qp if has_long_lines else utf8_charset
    MIMEText.set_payload(self, payload, charset=charset)
SafeMIMEText.set_payload = _29830_set_payload


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
    key_addresses = dict(
        (addr.address, addr.use_asc)
        for addr in Address.objects.filter(address__in=recipient_list)
        if addr.key.can_encrypt())
    if key_addresses:
        gpg = GPG()
    else:
        gpg = None

    # Load attachments and create name/data tuples.
    attachments_parts = []
    if attachments is not None:
        for attachment in attachments:
            if not isinstance(attachment, (list, tuple)):
                attachment = str(attachment)
                with open(attachment, "rb") as f:
                    attachments_parts.append((basename(attachment), f.read()))
            else:
                if len(attachment) != 2:
                    raise ValueError("Attachments can be pairs of name/data, or filesystem paths.")
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
                                        sign=SIGN,
                                        encrypt=addr_list[0] in key_addresses)
        if html_message is not None:
            msg.attach_alternative(html_message, "text/html")
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
        self.sign = kwargs.pop('sign', False)
        self.fail_silently = kwargs.pop('fail_silently', False)
        super().__init__(*args, **kwargs)

        if self.sign:
            encoding = self.encoding or settings.DEFAULT_CHARSET
            has_long_lines = any(len(line.encode(encoding)) > 76 for line in self.body.splitlines())
            if has_long_lines or re.search("^From |[ \t\r]$", self.body, re.M):
                if not isinstance(self.encoding, emailcharset.Charset):
                    self.encoding = emailcharset.Charset(encoding)
                self.encoding.body_encoding = emailcharset.QP

    def _create_mime_attachment(self, content, mimetype):
        basetype, subtype = mimetype.split('/', 1)
        if basetype == "text":
            encoding = self.encoding or settings.DEFAULT_CHARSET
            if not isinstance(encoding, emailcharset.Charset):
                encoding = emailcharset.Charset(encoding)
            encoding.body_encoding = emailcharset.QP
            return SafeMIMEText(content, subtype, encoding)
        else:
            return super()._create_mime_attachment(content, mimetype)

    def _create_message(self, msg):
        msg = super()._create_message(msg)
        if self.gpg is None:
            return msg
        if self.sign:
            sign_msg = msg
            sign_text = re.sub('\r?\n', '\r\n', sign_msg.as_string())
            if sign_msg.is_multipart() and not sign_text.endswith("\r\n"):
                sign_text += "\r\n"
            signature, sig_info = self.gpg.sign(
                sign_text.encode(),
                mode=constants.SIG_MODE_DETACH)
            if signature and sig_info.signatures:
                hash_algo = HASH_ALGORITHM[sig_info.signatures[0].hash_algo]
                msg = SafeMIMEMultipart(
                    _subtype="signed",
                    protocol="application/pgp-signature",
                    mictype="pgp-{}".format(hash_algo))
                msg.attach(sign_msg)
                sig = MIMEBase('application', 'pgp-signature', name='signature.asc')
                sig.add_header('Content-Disposition', 'attachment', filename='signature.asc')
                sig.add_header('Content-Description', 'Message signed with OpenPGP', filename='signature.asc')
                sig.set_payload(signature, 'ascii')
                msg.attach(sig)
            elif not self.fail_silently:
                raise ValueError("PGP signing failed")
        if self.encrypt:
            recipients = set()
            for to in self.to:
                keys = list(self.gpg.keylist(pattern=to))
                if not keys:
                    raise ValueError("Can not find key for address {}".format(to))
                recipients = recipients.union(keys)
            encrypted, enc_result, _ = self.gpg.encrypt(
                msg.as_bytes(), list(recipients), sign=False,
                always_trust=ALWAYS_TRUST)
            if encrypted and not enc_result.invalid_recipients:
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
                body.set_payload(encrypted, 'ascii')
                msg.attach(body)
                msg.preamble = "This is an OpenPGP/MIME encrypted message (RFC 2400 and 3156)"
            elif not self.fail_silently:
                raise ValueError("PGP encryption failed")
        return msg

