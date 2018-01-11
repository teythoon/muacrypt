"""
Storage layer which mainly provides the Store class through which
all application state is persistet.  The Store uses
Kappa architecture http://milinda.pathirage.org/kappa-architecture.com/
i.e. all changes are added to append-only logs ("chains") and they contain
immutable entries ("claims") that may cross-reference other entries (even
from other chains). The linking between entries is done using
crytographic hashes.  The HeadTracker keeps track of named "heads"
which can be queried through the Store class.  Both the current
BlockService and the HeadTracker use the file system for
persistent storage.
"""

from __future__ import unicode_literals
from __future__ import print_function

import os
from . import mime
from .storage_fs import HeadTracker, BlockService
from pprint import pprint
from .myattr import (
    v, attr, attrs, attrib, attrib_text, attrib_text, attrib_bytes,
    attrib_bytes_or_none, attrib_text_or_none, attrib_float,
)

# ==================================================
# Store
# =================================================


class Store:
    """ Persisting Muacrypt and per-account settings."""

    _account_pat = "."
    _own_pat = "own:{id}"
    _oob_pat = "oob:{id}"
    _peer_pat = "peer:{id}:{addr}"

    def __init__(self, dirpath):
        self.dirpath = dirpath
        blockdir = os.path.join(dirpath, "blocks")
        if not os.path.exists(blockdir):
            os.makedirs(blockdir)
        self.heads = HeadTracker(os.path.join(dirpath, "heads"))
        self.blocks = BlockService(blockdir)

    def get__accountmanager_chain(self):
        return AccountManagerChain(self.blocks, self.heads, self._account_pat)

    def get_accountmanager_state(self):
        return AccountManagerState(self.get__accountmanager_chain())

    def get_account_names(self):
        return sorted(self.heads._getheads(prefix=self._own_pat.format(id="")))

    def get_num_peers(self, account):
        return len(self.get_peername_list())

    def get_peername_list(self, account_name):
        prefix = self._peer_pat.format(id=account_name, addr="")
        return sorted(self.heads._getheads(prefix=prefix))

    def get_peerchain(self, account_name, addr):
        # XXX encode addr?
        assert addr.encode("ascii"), addr
        head_name = self._peer_pat.format(id=account_name, addr=addr)
        return PeerChain(self.blocks, self.heads, head_name)

    def get_peerstate(self, account_name, addr):
        return PeerState(self.get_peerchain(account_name, addr))

    def get_ownchain(self, account_name):
        head_name = self._own_pat.format(id=account_name)
        return OwnChain(self.blocks, self.heads, head_name)

    def get_ownstate(self, account_name):
        return OwnState(self.get_ownchain(account_name))

    def get_own_gpghome(self, account_name):
        return os.path.join(self.dirpath, "gpg", account_name)

    def get_oobchain(self, account_name):
        head_name = self._oob_pat.format(id=account_name)
        return OOBChain(self.blocks, self.heads, head_name)

    def get_oobstate(self, account_name):
        return OOBState(self.get_oobchain(account_name))

    def remove_account(self, account_name):
        def match_account(key, value):
            l = key.split(":", 2)
            if l[0] in ("own", "peer") and l[1] == account_name:
                return True
        self.heads.remove_if(match_account)


# ===========================================================
# Chain base classes and helpers
# ===========================================================

class ChainBase(object):
    """ A Chain maintains an append-only log where each entry
    in the chain has its own content-based address so that chains
    can cross-reference entries from the same or other chains. Each entry in a chain
    carries a timestamp and a parent CID (block hash) and type-specific
    extra data.
    """

    def __init__(self, blockservice, headtracker, chain_name):
        self._bs = blockservice
        self._ht = headtracker
        self.chain_name = chain_name

    def dump(self):
        l = list(self.get_head_block())
        for x in reversed(l):
            pprint("{} {}: {}".format(x.timestamp, x.type, shortrepr(x.args)))

    def is_empty(self):
        return not self.get_head_block()

    def new_head_block(self, type, args):
        head = self.get_head_block()
        if head:
            head = head.cid
        block = self._bs.store_block(type, args, parent=head)
        self._ht.upsert(self.chain_name, block.cid)
        return block

    def get_head_block(self):
        head_cid = self._ht.get_head_cid(self.chain_name)
        if head_cid:
            return self._bs.get_block(head_cid)

    def iter_blocks(self, type=None):
        """ yields blocks from head to root for this chain. """
        head_block = self.get_head_block()
        if head_block:
            for x in head_block:
                if type is None or x.type == type:
                    yield x

    def num_blocks(self):
        return len(list(self.iter_blocks()))

    def __len__(self):
        return len(list(self.iter_blocks()))

    def append_entry(self, entry):
        args = attr.astuple(entry)
        self.new_head_block(entry.TAG, args)

    def iter_entries(self, entryclass=None):
        assert entryclass is None or hasattr(entryclass, "TAG")
        tag = getattr(entryclass, "TAG", None)
        for block in self.iter_blocks():
            if block and (tag is None or block.type == tag):
                yield entryclass(*block.args)

    def latest_entry_of(self, entryclass):
        for entry in self.iter_entries(entryclass):
            return entry


def shortrepr(obj):
    r = repr(obj)
    if len(r) > 50:
        r = r[:23] + "..." + r[-23:]
    return r


# ===========================================================
# PeerChains for keeping track of incoming messages per peer
# ===========================================================

@attr.s
class MsgEntry(object):
    TAG = "msg"
    msg_id = attrib_text()
    msg_date = attrib_float()
    prefer_encrypt = attrib(validator=v.in_(['nopreference', 'mutual']))
    keydata = attrib_bytes()
    keyhandle = attrib_text()


class PeerChain(ChainBase):
    def latest_ac_entry(self):
        """ Return latest message with Autocrypt header. """
        for entry in self.iter_entries(MsgEntry):
            if entry.keydata:
                return entry

    def latest_msg_entry(self):
        """ Return latest message with or without Autocrypt header. """
        return self.latest_entry_of(MsgEntry)

    def append_ac_entry(self, msg_id, msg_date, prefer_encrypt, keydata, keyhandle):
        """append an Autocrypt message entry. """
        self.append_entry(MsgEntry(
            msg_id=msg_id, msg_date=msg_date, prefer_encrypt=prefer_encrypt,
            keydata=keydata, keyhandle=keyhandle))

    def append_noac_entry(self, msg_id, msg_date):
        """append a non-Autocrypt message entry. """
        self.append_entry(MsgEntry(
            msg_id=msg_id, msg_date=msg_date,
            prefer_encrypt="nopreference", keyhandle="", keydata=b""
        ))


@attrs
class PeerState(object):
    """Synthesized Autocrypt state from parsing messages from a peer. """
    _peerchain = attrib()

    def __str__(self):
        return "PeerState addr={addr} key={keyhandle}".format(
            addr=self.addr, keyhandle=self.public_keyhandle
        )

    @property
    def addr(self):
        return self._peerchain.chain_name.split(":", 2)[-1]

    @property
    def last_seen(self):
        return getattr(self._peerchain.latest_msg_entry(), "msg_date", 0.0)

    @property
    def autocrypt_timestamp(self):
        return getattr(self._peerchain.latest_ac_entry(), "msg_date", 0.0)

    @property
    def public_keyhandle(self):
        return getattr(self._peerchain.latest_ac_entry(), "keyhandle", None)

    @property
    def public_keydata(self):
        return getattr(self._peerchain.latest_ac_entry(), "keydata", None)

    # methods which modify/add state
    def update_from_msg(self, msg_id, effective_date, parsed_autocrypt_header,
                        keydata, keyhandle):
        if parsed_autocrypt_header and effective_date >= self.autocrypt_timestamp:
            self._peerchain.append_ac_entry(
                msg_id=msg_id, msg_date=effective_date,
                prefer_encrypt=parsed_autocrypt_header["prefer-encrypt"],
                keydata=keydata or b'', keyhandle=keyhandle or '',
            )
        else:
            if effective_date > self.last_seen:
                self._peerchain.append_noac_entry(
                    msg_id=msg_id, msg_date=effective_date,
                )



# ===========================================================
# OwnChain keeps track of own crypto settings
# ===========================================================

def config_property(name):
    def get(self):
        return getattr(self._ownchain.latest_config(), name)
    return property(get)

@attr.s
class KeygenEntry(object):
    TAG = "keygen"
    keydata = attrib_bytes_or_none()
    keyhandle = attrib_text_or_none()


@attr.s
class OwnConfigEntry(object):
    TAG = "cfg"
    prefer_encrypt = attrib(validator=v.in_(['nopreference', 'mutual']))
    name = attrib_text()
    email_regex = attrib_text()
    gpgmode = attrib(validator=v.in_(['system', 'own']))
    gpgbin = attrib_text()


class OwnChain(ChainBase):
    def append_keygen(self, keydata, keyhandle):
        self.append_entry(KeygenEntry(
            keydata=keydata,
            keyhandle=keyhandle
        ))

    def latest_keygen(self):
        return self.latest_entry_of(KeygenEntry)

    def latest_config(self):
        return self.latest_entry_of(OwnConfigEntry)

    def new_config(self, name, prefer_encrypt, email_regex, gpgmode, gpgbin):
        self.append_entry(OwnConfigEntry(
            name=name, prefer_encrypt=prefer_encrypt, email_regex=email_regex,
            gpgmode=gpgmode, gpgbin=gpgbin,
        ))

    def change_config(self, **kwargs):
        entry = self.latest_config()
        new_entry = attr.evolve(entry, **kwargs)
        if new_entry != entry:
            self.append_entry(new_entry)
            return True


@attrs
class OwnState(object):
    """Synthesized own state for an account. """
    _ownchain = attrib()

    def __str__(self):
        return "OwnState key={keyhandle}".format(
            keyhandle=self.keyhandle,
        )
    name = config_property("name")
    email_regex = config_property("email_regex")
    gpgmode = config_property("gpgmode")
    gpgbin = config_property("gpgbin")
    prefer_encrypt = config_property("prefer_encrypt")

    @property
    def keyhandle(self):
        return self._ownchain.latest_keygen().keyhandle

    def exists(self):
        return self.name

    # methods which modify/add state
    def new_config(self, name, prefer_encrypt, email_regex, gpgmode, gpgbin):
        return self._ownchain.new_config(
            name=name, prefer_encrypt=prefer_encrypt, email_regex=email_regex,
            gpgmode=gpgmode, gpgbin=gpgbin,
        )

    def change_config(self, **kwargs):
        return self._ownchain.change_config(**kwargs)

    def append_keygen(self, **kwargs):
        return self._ownchain.append_keygen(**kwargs)

    def is_configured(self):
        return self._ownchain.latest_config() and self._ownchain.latest_keygen()


# ===========================================================
# OOBChain keeps track of out-of-band verifications
# ===========================================================

@attr.s
class VerificationEntry(object):
    TAG = "oobverify"
    addr = attrib_text()
    public_keydata = attrib_bytes()
    origin = attrib(validator=v.in_(["self", "peer"]))


class OOBChain(ChainBase):
    pass


@attrs
class OOBState(object):
    """Synthesized own state for an account. """
    _oobchain = attrib()

    def __str__(self):
        return "OOBState key={keyhandle}".format(
            keyhandle=self.keyhandle,
        )

    def get_verification(self, addr):
        for entry in self._oobchain.iter_entries(VerificationEntry):
            if addr == entry.addr:
                return entry


    def append_self_verification(self, addr, public_keydata):
        self._oobchain.append_entry(VerificationEntry(
            addr=addr,
            public_keydata=public_keydata,
            origin="self",
        ))
    def append_peer_verification(self, addr, public_keydata):
        self._oobchain.append_entry(VerificationEntry(
            addr=addr,
            public_keydata=public_keydata,
            origin="peer",
        ))



# ===========================================================
# AccountManagerChain keeps track of account modifications
# ===========================================================

@attr.s
class AConfigEntry(object):
    TAG = "acfg"
    version = attrib_text()


class AccountManagerChain(ChainBase):
    def set_version(self, version):
        assert not self.latest_config()
        self.append_entry(AConfigEntry(version=version))

    def latest_config(self):
        return self.latest_entry_of(AConfigEntry)


@attrs
class AccountManagerState(object):
    """Synthesized AccountManagerState. """
    _accountmanager_chain = attrib()

    @property
    def version(self):
        return getattr(self._accountmanager_chain.latest_config(), "version", None)

    def __str__(self):
        return "AccountManagerState version={version}".format(version=self.version)

    def set_version(self, version):
        return self._accountmanager_chain.set_version(version)
