"""irctest controller for Nefarious IRCd (evilnet/nefarious2 fork).

Nefarious is an ircu-derivative with extensive IRCv3 extensions.
This controller replaces the upstream stub that inherits from Ircu2Controller
with zero customization, so that irctest actually exercises the IRCv3 features.
"""

import shutil
from typing import Optional, Type

from irctest.basecontrollers import (
    BaseServerController,
    DirectoryBasedController,
    NotImplementedByController,
)
from irctest.specifications import Capabilities, OptionalBehaviors

TEMPLATE_CONFIG = """\
General {{
    name = "My.Little.Server";
    numeric = 42;
    description = "irctest instance";
}};

Port {{
    vhost = "{hostname}";
    port = {port};
}};

{ssl_config}

Class {{
    name = "Client";
    pingfreq = 5 minutes;
    sendq = 160000;
    maxlinks = 1024;
    fakelagminimum = 0;
    fakelagfactor = 0;
}};

Client {{
    username = "*";
    class = "Client";
    {password_field}
}};

Operator {{
    local = no;
    host = "*@*";
    password = "$PLAIN$operpassword";
    name = "operuser";
    class = "Client";
}};

features {{
    "PPATH" = "{pidfile}";
    "HIS_SERVERNAME" = "My.Little.Server";
    "MSGID" = "TRUE";
    "HOST_HIDING" = "FALSE";
    "NOIDENT" = "TRUE";
    # Default NICKDELAY of 30s tank tests that rapid-fire NICK changes
    # (e.g. MONITOR's testNickChange).  Disable for testing.
    "NICKDELAY" = "0";
    "CONNEXIT_NOTICES" = "FALSE";
    "CAP_server_time" = "TRUE";
    "CAP_echo_message" = "TRUE";
    "CAP_batch" = "TRUE";
    "CAP_labeled_response" = "TRUE";
    "CAP_message_tags" = "TRUE";
    "CAP_account_tag" = "TRUE";
    "CAP_setname" = "TRUE";
    "CAP_multi_prefix" = "TRUE";
    "CAP_extended_join" = "TRUE";
    "CAP_away_notify" = "TRUE";
    "CAP_account_notify" = "TRUE";
    "CAP_cap_notify" = "TRUE";
    "CAP_standard_replies" = "TRUE";
    "CAP_chghost" = "TRUE";
    "CAP_invite_notify" = "TRUE";
    "CAP_sasl" = "TRUE";
    "CAP_draft_multiline" = "TRUE";
    "CAP_draft_message_redaction" = "TRUE";
    "CAP_draft_chathistory" = "TRUE";
    "CAP_draft_read_marker" = "TRUE";
    "CAP_draft_channel_rename" = "TRUE";
    "CAP_draft_metadata_2" = "TRUE";
    "EXCEPTS" = "TRUE";
    # CHATHISTORY_DB is a path string (default "history"), not a bool —
    # explicitly point at a per-test directory so the RocksDB env opens
    # cleanly without a leftover relative "history/" under whatever cwd
    # ircd launched in.
    "CHATHISTORY_DB" = "{chathistory_db}";
    "CHATHISTORY_STORE" = "TRUE";
    "CHATHISTORY_PRIVATE" = "TRUE";
    {ssl_features}
}};
"""

TEMPLATE_SSL_CONFIG = """\
Port {{
    vhost = "{hostname}";
    port = {ssl_port};
    ssl = yes;
}};
"""

TEMPLATE_SSL_FEATURES = """\
    "SSL_CERTFILE" = "{ssl_pem}";
    "SSL_KEYFILE" = "{ssl_pem}";
    "CAP_tls" = "TRUE";
"""


class NefariousController(BaseServerController, DirectoryBasedController):
    software_name = "Nefarious"
    supports_sts = False
    extban_mute_char = None

    # All IRCv3 capabilities nefarious supports that are in the Capabilities enum
    capabilities = frozenset(
        {
            Capabilities.ACCOUNT_NOTIFY,
            Capabilities.ACCOUNT_TAG,
            Capabilities.AWAY_NOTIFY,
            Capabilities.BATCH,
            Capabilities.ECHO_MESSAGE,
            Capabilities.EXTENDED_JOIN,
            Capabilities.LABELED_RESPONSE,
            Capabilities.MESSAGE_REDACTION,
            Capabilities.MESSAGE_TAGS,
            Capabilities.MULTILINE,
            Capabilities.MULTI_PREFIX,
            Capabilities.SERVER_TIME,
            Capabilities.SETNAME,
        }
    )

    optional_behaviors = frozenset(
        {
            OptionalBehaviors.BAN_EXCEPTION_MODE,
            OptionalBehaviors.INVITE_OVERRIDES_LIMIT,
        }
    )

    def create_config(self) -> None:
        super().create_config()
        with self.open_file("server.conf"):
            pass

    def run(
        self,
        hostname: str,
        port: int,
        *,
        password: Optional[str],
        ssl: bool,
        run_services: bool,
        faketime: Optional[str],
        websocket_hostname: Optional[str],
        websocket_port: Optional[int],
    ) -> None:
        if websocket_hostname is not None or websocket_port is not None:
            raise NotImplementedByController("Websocket")
        if run_services:
            raise NotImplementedByController("Services")
        assert self.proc is None
        self.port = port
        self.hostname = hostname
        self.create_config()

        password_field = 'password = "{}";'.format(password) if password else ""
        assert self.directory
        pidfile = self.directory / "ircd.pid"

        # SSL setup: nefarious tries to load SSL_CERTFILE (default
        # "ircd.pem") at startup regardless of any SSL listener, and
        # exits with "Failed to initialize SSL contexts" if the file
        # is missing.  Generate the PEM unconditionally so the bare
        # plaintext-only test path also starts cleanly; only emit the
        # SSL listener block + features overrides when the caller
        # actually requested SSL.
        self.gen_ssl()
        ssl_pem = self.directory / "ircd.pem"
        with open(ssl_pem, "w") as out:
            out.write(self.key_path.read_text())
            out.write(self.pem_path.read_text())

        ssl_config = ""
        ssl_features = TEMPLATE_SSL_FEATURES.format(ssl_pem=ssl_pem)
        if ssl:
            (ssl_hostname, ssl_port) = self.get_hostname_and_port()
            ssl_config = TEMPLATE_SSL_CONFIG.format(
                hostname=hostname,
                ssl_port=ssl_port,
            )

        with self.open_file("server.conf") as fd:
            fd.write(
                TEMPLATE_CONFIG.format(
                    hostname=hostname,
                    port=port,
                    password_field=password_field,
                    pidfile=pidfile,
                    ssl_config=ssl_config,
                    ssl_features=ssl_features,
                    chathistory_db=str(self.directory / "history"),
                )
            )

        if faketime and shutil.which("faketime"):
            faketime_cmd = ["faketime", "-f", faketime]
            self.faketime_enabled = True
        else:
            faketime_cmd = []

        self.proc = self.execute(
            [
                *faketime_cmd,
                "ircd",
                "-n",  # don't detach
                "-f",
                self.directory / "server.conf",
                "-x",
                "DEBUG",
            ],
        )


def get_irctest_controller_class() -> Type[NefariousController]:
    return NefariousController
