import logging
from collections import namedtuple

import zope.interface
from certbot import errors, interfaces
from certbot.plugins import dns_common
from dnspod_sdk import DnspodClient

logger = logging.getLogger(__name__)

DomainInfo = namedtuple("DomainInfo", ["id", "name"])


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for DNSPod

    This Authenticator uses the DNSPod API to fulfill a dns-01 challenge.
    """

    description = "使用DNS TXT记录获取证书（如果使用DNSPod管理DNS）"

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add("credentials", help="DNSPod credentials INI file.")

    def more_info(self):  # pylint: disable=missing-function-docstring
        return "This plugin configures a DNS TXT record to respond to a dnspod " "challenge using the DNSPod API."

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "DNSPod credentials INI file",
            {"token_id": "API token_id for DNSPod account", "token": "API token for DNSPod account"},
        )

    def _perform(self, domain, validation_name, validation):
        self._get_dnspod_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_dnspod_client().del_txt_record(domain, validation_name, validation)

    def _get_dnspod_client(self):
        return _DNSPodClient(self.credentials.conf("token_id"), self.credentials.conf("token"))


class _DNSPodClient(object):
    """
    Encapsulates all communication with the DNSPod API.
    """

    def __init__(self, token_id, token):
        user_agent = "Certbot DNS Plugins/1.0(me@codeif.com))"
        self.dc = DnspodClient(token_id, token, user_agent)

    def add_txt_record(self, domain_name, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the DNSPod API
        """
        domain_info = self._find_domain_info(domain_name)
        data = {
            "domain_id": domain_info.id,
            "sub_domain": self.get_sub_domain(record_name, domain_info),
            "record_type": "TXT",
            "value": record_content,
            "record_line": "默认",
        }
        j = self.dc.post("/Record.Create", data=data).json()
        self._check_response(j)

    def del_txt_record(self, domain_name, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """
        domain_info = self._find_domain_info(domain_name)
        record_sub_domain = self.get_sub_domain(record_name, domain_info)
        record_ids = self._find_record_ids(domain_info.id, record_sub_domain)
        for record_id in record_ids:
            data = {
                "domain_id": domain_info.id,
                "record_id": record_id,
            }
            j = self.dc.post("/Record.Remove", data=data).json()
            self._check_response(j)

    def _check_response(self, j):
        status = j["status"]
        code = int(status["code"])
        if code != 1:
            raise errors.PluginError(f'DNSPod API response error, code-{code}, message-{status["message"]}')

    def get_sub_domain(self, record_name, domain_info):
        return record_name[0 : -len(domain_info.name) - 1]

    def _find_domain_info(self, domain_name):
        """
        Find the domain object for a given domain name.

        :param str domain_name: The domain name for which to find the corresponding Domain.
        :returns: The Domain, if found.
        :rtype: `~dnspod.DomainInfo`
        :raises certbot.errors.PluginError: if no matching Domain is found.
        """
        j = self.dc.post("/Domain.List").json()
        self._check_response(j)
        for domain_obj in j["domains"]:
            if domain_name.endswith(domain_obj["name"]):
                return DomainInfo(domain_obj["id"], domain_obj["name"])
        assert False, f"_find_domain_info() Can't find domain: {domain_name}"

    def _find_record_ids(self, domain_id, sub_domain):
        data = {
            "domain_id": domain_id,
            "sub_domain": sub_domain,
            "record_type": "TXT",
        }
        j = self.dc.post("/Record.List", data=data).json()
        code = int(j["status"]["code"])
        if code == 10:
            # 'code': '10', 'message': '记录列表为空'
            return []
        self._check_response(j)
        return [x["id"] for x in j["records"]]
