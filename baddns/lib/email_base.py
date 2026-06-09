import logging

import tldextract

from baddns.base import BadDNS_base
from baddns.lib.dnsmanager import DNSManager

log = logging.getLogger(__name__)


class BadDNS_email_base(BadDNS_base):
    """Shared base for email-related modules (DMARC, SPF, MTA-STS).

    Provides an MX-presence check so callers can skip checks that only matter
    for domains that actually receive mail. The target's own MX takes precedence;
    if absent, the registered (apex) domain is consulted, since email infra is
    typically organizational rather than per-leaf-subdomain.
    """

    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)
        self.disable_mx_gate = kwargs.get("disable_mx_gate", False)
        self._mx_present_cache = None

    async def has_email_infra(self):
        """True if the target or its registered domain has any MX records."""
        if self._mx_present_cache is not None:
            return self._mx_present_cache

        mx_omit = ["A", "AAAA", "CNAME", "NS", "SOA", "TXT", "NSEC"]

        sub_dns = DNSManager(self.target, dns_client=self.dns_client, custom_nameservers=self.custom_nameservers)
        await sub_dns.dispatchDNS(omit_types=mx_omit)
        if sub_dns.answers.get("MX"):
            self._mx_present_cache = True
            return True

        registered_domain = tldextract.extract(self.target).registered_domain
        if registered_domain and registered_domain != self.target:
            apex_dns = DNSManager(
                registered_domain, dns_client=self.dns_client, custom_nameservers=self.custom_nameservers
            )
            await apex_dns.dispatchDNS(omit_types=mx_omit)
            if apex_dns.answers.get("MX"):
                self._mx_present_cache = True
                return True

        self._mx_present_cache = False
        return False

    async def mx_gate_skips(self):
        """True if the module should skip its email-config checks due to no MX.

        Returns False when the gate is disabled via disable_mx_gate.
        """
        if self.disable_mx_gate:
            return False
        if await self.has_email_infra():
            return False
        log.debug(
            f"Skipping email checks for [{self.target}] in [{self.__class__.__name__}] - no MX at target or apex"
        )
        return True
