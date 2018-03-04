# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

"""
Bot command line subcommand to receive and answer with Autocrypt related
information for mails to bot@autocrypt.org
"""
from __future__ import print_function

import sys
import six
import traceback
import contextlib
from . import mime
from .cmdline_utils import (
    get_account_manager, mycommand, click, trunc_string
)


def send_reply(host, port, msg):
    import smtplib
    smtp = smtplib.SMTP(host, port)
    return smtp.sendmail(msg["From"], msg["To"], msg.as_string())


@mycommand("bot-reply")
@click.option("--smtp", default=None, metavar="host,port",
              help="host and port where the reply should be "
                   "instead of to stdout.")
@click.option("--fallback-delivto", default=None,
              help="assume delivery to the specified email address if "
                   "no delivered-to header is found.")
@click.pass_context
def bot_reply(ctx, smtp, fallback_delivto):
    """reply to stdin mail as a bot.

    This command will generate a reply message and send it to stdout by default.
    The reply message contains an Autocrypt header and details of what
    was found and understood from the incoming mail.
    """
    account_manager = get_account_manager(ctx)
    msg = mime.parse_message_from_file(sys.stdin)
    From = msg["From"]
    reply_to_encrypted = msg.get_content_type() == "multipart/encrypted"
    ac = 'Autocrypt' in msg
    delivto = mime.get_delivered_to(msg, fallback_delivto)
    account = account_manager.get_account_from_emailadr(delivto)
    r = account.process_incoming(msg)

    recom = account.get_recommendation([From], reply_to_encrypted)
    ui_recommendation = recom.ui_recommendation()
    i_will_encrypt = ui_recommendation == 'encrypt'

    if ac:
        if not reply_to_encrypted:
            if i_will_encrypt:
                m = """
You have successfully installed an Autocrypt-capable mail client and
sent an email to me.  I am sending you this email encrypted.

If you reply to this email, your reply will also be encrypted.

Well done!
"""
            else:
                m = """
You have successfully installed an Autocrypt-capable mail client and
sent an email to me.  It is now possible for me to send you encrypted
email.

If you send me an encrypted email I will reply encrypted.
"""
        else: # reply_to_encrypted
            m = """
Thanks for the encrypted mail.  Now we are having an encrypted email
conversation.

Well done!
"""
    else: # not ac
        if not reply_to_encrypted:
            m = """
I do not believe that you are using an Autocrypt-capable mail client.
"""
        else:
            m = """
You encrypted a mail to me, but you are not using an
Autocrypt-capable mail client.  You certainly are an OpenPGP ninja.
"""

    m = """Hello {0} :)
{1}

Enjoy the rest of the IFF :)
""".format(From, m)

    reply_msg = mime.gen_mail_msg(
        From=delivto, To=[From],
        Subject="Re: " + msg["Subject"],
        _extra={"In-Reply-To": msg["Message-ID"]},
        Autocrypt=account.make_ac_header(delivto),
        payload=six.text_type(m), charset="utf8",
    )
    if ui_recommendation == 'encrypt':
        r = account.encrypt_mime(reply_msg, [From])
        reply_msg = r.enc_msg
    if smtp:
        host, port = smtp.split(",")
        send_reply(host, int(port), reply_msg)
        click.echo("send reply through smtp: {}".format(smtp))
    else:
        click.echo(reply_msg.as_string())


class SimpleLog:
    def __init__(self):
        self.logs = []
        self._indent = 0

    @property
    def indent(self):
        return u"  " * self._indent

    def __call__(self, msg=""):
        lines = msg.splitlines()
        if not lines:
            lines = [u""]
        self.logs.append(self.indent + lines[0])
        self.logs.extend([(self.indent + line) for line in lines[1:]])

    @contextlib.contextmanager
    def s(self, title, raising=False):
        # one extra empty line before a section
        if self.logs:
            self("")
        self(title)
        self()
        self._indent += 1
        try:
            try:
                yield
            finally:
                self._indent -= 1
        except Exception:
            if raising:
                raise
            self(traceback.format_exc())
        # one extra empty line after a section
        self("")

    def __str__(self):
        return "\n".join(self.logs)
