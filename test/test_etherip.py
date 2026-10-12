#!/usr/bin/env python3
"""EtherIP (RFC 3378) tunnel plugin tests.

These tests depend on the external interface of the EtherIP plugin as
defined by the specification v0.4 (sections 4, 5 and 7): interface naming,
binary API, CLI, wire format, receive-side drop order and error counters.
"""

import re
import unittest
from ipaddress import ip_address

from scapy.fields import BitField
from scapy.packet import Packet, Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP, IPOption_NOP, IPOption_Router_Alert
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment

from framework import VppTestCase, Send, Expect
from asfframework import VppTestRunner
from vpp_interface import VppInterface
from vpp_object import VppObject
from vpp_ip_route import VppIpTable
from vpp_l2 import (
    VppBridgeDomain,
    VppBridgeDomainPort,
    find_bridge_domain_port,
    find_l2_fib_entry,
)
from vpp_papi import VppEnum
from vpp_papi_provider import (
    CliFailedCommandError,
    CliSyntaxError,
    UnexpectedApiReturnValueError,
)
from config import config

IP_PROTO_ETHERIP = 97
IP6_NH_FRAGMENT = 44
ETHERIP_HEADER = 0x3000
ETHERIP_HEADER_BYTES = b"\x30\x00"
INSTANCE_AUTO = 0xFFFFFFFF
INDEX_INVALID = 0xFFFFFFFF
DEFAULT_HOP_LIMIT = 64
TUNNEL_SW_MTU = 9000

# packets per stream in the main tests.  The encap and decap nodes handle
# one buffer per loop iteration; 63 is not a multiple of 2, 4 or 8, so a
# later dual / quad loop would also have to run its remainder path.
N_PKTS = 63
# packets per stream in the drop and parameter tests
N_ERR = 7

INNER_SRC_MAC = "02:00:00:00:10:01"
INNER_DST_MAC = "02:00:00:00:10:02"
INNER_SRC_IP4 = "192.0.2.1"
INNER_DST_IP4 = "192.0.2.2"
# MAC of a host behind the remote tunnel endpoint (bridge domain test)
REMOTE_HOST_MAC = "02:00:00:00:20:02"
BD_ID = 10

# error.def: symbolic name -> description string
ETHERIP_ERRORS = {
    "DECAP": "packets decapsulated",
    "ENCAP": "packets encapsulated",
    "TOO_SHORT": "packet too short",
    "BAD_HEADER": "bad EtherIP header",
    "NO_SUCH_TUNNEL": "no such tunnel",
    "TUNNEL_DOWN": "tunnel admin down",
    "POLICY_DROP": "dropped by allow policy",
    # optional (spec v0.4 7.1.4), counted by etherip-encap
    "TX_DOWN": "tunnel admin down (tx)",
}

# counters incremented by etherip4-input / etherip6-input
DECAP_COUNTERS = (
    "DECAP",
    "TOO_SHORT",
    "BAD_HEADER",
    "NO_SUCH_TUNNEL",
    "TUNNEL_DOWN",
    "POLICY_DROP",
)

ENCAP_NODE = "etherip-encap"


class EtherIPHeader(Packet):
    """RFC 3378 EtherIP header: 4 bit version + 12 bit reserved.

    Defined here and intentionally not bound to IP / IPv6 / Ether, so that
    the tests do not depend on scapy.contrib.etherip or on scapy bindings.
    """

    name = "EtherIP header (test)"
    fields_desc = [BitField("version", 3, 4), BitField("reserved", 0, 12)]


def etherip_header(value=ETHERIP_HEADER):
    """Return an EtherIPHeader whose 16 bit wire value is `value`."""
    return EtherIPHeader(version=(value >> 12) & 0xF, reserved=value & 0xFFF)


def same_addr(a, b):
    return ip_address(str(a)) == ip_address(str(b))


def etherip_tunnel_args(
    src,
    dst,
    outer_table_id=0,
    instance=INSTANCE_AUTO,
    hop_limit=0,
    dscp=0,
    set_df=False,
):
    """vl_api_etherip_tunnel_t as a dict (sw_if_index is left to its default)."""
    return {
        "instance": instance,
        "src": str(src),
        "dst": str(dst),
        "outer_table_id": outer_table_id,
        "hop_limit": hop_limit,
        "dscp": int(dscp),
        "set_df": set_df,
    }


class VppEtherIPTunnel(VppInterface):
    """VPP EtherIP tunnel interface (etherip_tunnel_add_del / _dump)."""

    def __init__(
        self,
        test,
        src,
        dst,
        outer_table_id=0,
        instance=INSTANCE_AUTO,
        hop_limit=0,
        dscp=0,
        set_df=False,
    ):
        super(VppEtherIPTunnel, self).__init__(test)
        self.src = str(src)
        self.dst = str(dst)
        self.outer_table_id = outer_table_id
        self.instance = instance
        self.hop_limit = hop_limit
        self.dscp = int(dscp)
        self.set_df = set_df
        # underlay pg interface and MAC of the remote endpoint, set by tests
        self.underlay = None
        self.peer_mac = None

    def add_vpp_config(self):
        r = self.test.vapi.etherip_tunnel_add_del(
            is_add=True,
            tunnel=etherip_tunnel_args(
                self.src,
                self.dst,
                outer_table_id=self.outer_table_id,
                instance=self.instance,
                hop_limit=self.hop_limit,
                dscp=self.dscp,
                set_df=self.set_df,
            ),
        )
        self.set_sw_if_index(r.sw_if_index)
        self.test.registry.register(self, self.test.logger)
        return self

    def remove_vpp_config(self):
        # the key is (outer_table_id, src, dst); the other fields are ignored
        self.test.vapi.etherip_tunnel_add_del(
            is_add=False,
            tunnel=etherip_tunnel_args(
                self.src, self.dst, outer_table_id=self.outer_table_id
            ),
        )

    def get_details(self):
        """Return this tunnel's etherip_tunnel_details, or None."""
        for d in self.test.vapi.etherip_tunnel_dump(sw_if_index=INDEX_INVALID):
            if d.tunnel.sw_if_index == self.sw_if_index:
                return d
        return None

    def query_vpp_config(self):
        d = self.get_details()
        return (
            d is not None
            and same_addr(d.tunnel.src, self.src)
            and same_addr(d.tunnel.dst, self.dst)
            and d.tunnel.outer_table_id == self.outer_table_id
        )

    def object_id(self):
        return "etherip-%d-%s-%s-%d" % (
            self.sw_if_index,
            self.src,
            self.dst,
            self.outer_table_id,
        )


class VppL2Xconnect(VppObject):
    """Bidirectional L2 cross-connect between two interfaces."""

    def __init__(self, test, if_a, if_b):
        self._test = test
        self.if_a = if_a
        self.if_b = if_b

    def add_vpp_config(self):
        for rx, tx in ((self.if_a, self.if_b), (self.if_b, self.if_a)):
            self._test.vapi.sw_interface_set_l2_xconnect(
                rx.sw_if_index, tx.sw_if_index, enable=1
            )
        self._test.registry.register(self, self._test.logger)
        return self

    def remove_vpp_config(self):
        for rx, tx in ((self.if_a, self.if_b), (self.if_b, self.if_a)):
            try:
                self._test.vapi.sw_interface_set_l2_xconnect(
                    rx.sw_if_index, tx.sw_if_index, enable=0
                )
            except UnexpectedApiReturnValueError as e:
                # the tunnel side may already have been deleted
                self._test.logger.info("l2 xconnect disable failed: %s" % e)

    def query_vpp_config(self):
        pairs = {
            (x.rx_sw_if_index, x.tx_sw_if_index)
            for x in self._test.vapi.l2_xconnect_dump()
        }
        a = self.if_a.sw_if_index
        b = self.if_b.sw_if_index
        return (a, b) in pairs or (b, a) in pairs

    def object_id(self):
        return "l2xc-%d-%d" % (self.if_a.sw_if_index, self.if_b.sw_if_index)


class EtherIPCountersMixin:
    """Helpers to read EtherIP error counters."""

    @staticmethod
    def etherip_err_paths(node, name):
        """Candidate stats paths of EtherIP error counter `name` on `node`.

        error.def is written in the legacy (symbol, description) form, so the
        stats path is /err/<node>/<description>.  The lower-case symbolic
        name is accepted as a fallback.
        """
        return (
            "/err/%s/%s" % (node, ETHERIP_ERRORS[name]),
            "/err/%s/%s" % (node, name.lower()),
        )

    def etherip_err_or_none(self, node, name):
        """Value of EtherIP error counter `name` on `node`, None if absent."""
        for path in self.etherip_err_paths(node, name):
            try:
                return int(self.statistics.get_err_counter(path))
            except KeyError:
                continue
        return None

    def etherip_err(self, node, name):
        """Value of EtherIP error counter `name` on `node` (must exist)."""
        value = self.etherip_err_or_none(node, name)
        if value is None:
            self.fail(
                "EtherIP error counter not found, tried %s"
                % (self.etherip_err_paths(node, name),)
            )
        return value

    def decap_snapshot(self, node):
        return {n: self.etherip_err(node, n) for n in DECAP_COUNTERS}

    def decap_diff(self, node, before):
        after = self.decap_snapshot(node)
        return {
            n: after[n] - before[n] for n in DECAP_COUNTERS if after[n] != before[n]
        }


class EtherIPTestMixin(EtherIPCountersMixin):
    """EtherIP test logic shared by the IPv4-outer and IPv6-outer classes.

    Topology:
      pg0: L2 port A (x-connected to the tunnel under test)
      pg1: underlay, IPv4 + IPv6, table 0, 8 remote hosts with neighbors
      pg2: underlay, IPv4 + IPv6, table 1, 1 remote host with neighbor
      pg3: L2 port B
    """

    is_ip6 = False

    @classmethod
    def setUpClass(cls):
        super(EtherIPTestMixin, cls).setUpClass()
        cls.create_pg_interfaces(range(4))
        cls.pg1.generate_remote_hosts(8)

        # record the allow switch before any test changes it
        cls.initial_allow = None
        cls.initial_allow_error = None
        try:
            cls.initial_allow = cls.vapi.etherip_get_allow().enable
        except Exception as e:  # reported by test_allow_default_off
            cls.initial_allow_error = e

    @classmethod
    def tearDownClass(cls):
        super(EtherIPTestMixin, cls).tearDownClass()

    def setUp(self):
        super(EtherIPTestMixin, self).setUp()

        # receive is refused by default; the receive tests need it on.
        self.saved_allow = self.vapi.etherip_get_allow().enable
        self.vapi.etherip_set_allow(enable=True)

        self.tbl4 = VppIpTable(self, 1, register=False).add_vpp_config()
        self.tbl6 = VppIpTable(self, 1, is_ip6=1, register=False).add_vpp_config()

        for i in self.pg_interfaces:
            i.admin_up()

        self.pg2.set_table_ip4(1)
        self.pg2.set_table_ip6(1)
        for i in (self.pg1, self.pg2):
            i.config_ip4()
            i.config_ip6()
            i.disable_ipv6_ra()
            i.configure_ipv4_neighbors()
            i.configure_ipv6_neighbors()

    def tearDown(self):
        if not self.vpp_dead:
            try:
                self.vapi.etherip_set_allow(enable=self.saved_allow)
            except Exception as e:
                self.logger.error("restoring etherip allow failed: %r" % e)
        try:
            super(EtherIPTestMixin, self).tearDown()
        finally:
            if not self.vpp_dead:
                self.remove_leftover_tunnels()
                for i in (self.pg1, self.pg2):
                    i.unconfig_ip4()
                    i.unconfig_ip6()
                self.pg2.set_table_ip4(0)
                self.pg2.set_table_ip6(0)
                for i in self.pg_interfaces:
                    i.admin_down()
                self.tbl4.remove_vpp_config()
                self.tbl6.remove_vpp_config()

    def remove_leftover_tunnels(self):
        """Delete tunnels not tracked by the registry (e.g. created by CLI)."""
        try:
            leftovers = self.vapi.etherip_tunnel_dump(sw_if_index=INDEX_INVALID)
        except Exception as e:
            self.logger.error("etherip_tunnel_dump failed in tearDown: %r" % e)
            return
        for d in leftovers:
            t = d.tunnel
            self.logger.info("removing leftover etherip sw_if_index %d" % t.sw_if_index)
            try:
                self.vapi.etherip_tunnel_add_del(
                    is_add=False,
                    tunnel=etherip_tunnel_args(
                        t.src, t.dst, outer_table_id=t.outer_table_id
                    ),
                )
            except Exception as e:
                self.logger.error("leftover etherip removal failed: %r" % e)

    #
    # address family helpers
    #
    def local_addr(self, intf):
        return intf.local_ip6 if self.is_ip6 else intf.local_ip4

    def host_addr(self, host):
        return host.ip6 if self.is_ip6 else host.ip4

    def other_af_host_addr(self, host):
        return host.ip4 if self.is_ip6 else host.ip6

    def local_prefix(self, intf):
        return intf.local_ip6_prefix if self.is_ip6 else intf.local_ip4_prefix

    def decap_node(self):
        return "etherip6-input" if self.is_ip6 else "etherip4-input"

    def outer_header(self, src, dst):
        if self.is_ip6:
            return IPv6(src=src, dst=dst, nh=IP_PROTO_ETHERIP, hlim=64)
        return IP(src=src, dst=dst, proto=IP_PROTO_ETHERIP, ttl=64)

    #
    # packet builders
    #
    def make_frames(self, count, start=0):
        """Return `count` distinct inner Ethernet frames (60 to 259 bytes)."""
        frames = []
        for i in range(start, start + count):
            f = (
                Ether(src=INNER_SRC_MAC, dst=INNER_DST_MAC)
                / IP(src=INNER_SRC_IP4, dst=INNER_DST_IP4)
                / UDP(sport=1024 + i, dport=5000)
                / Raw(bytes([i & 0xFF]) * (18 + (i * 7) % 200))
            )
            frames.append(Ether(bytes(f)))
        return frames

    def make_frame_of_len(self, length):
        """Return one inner Ethernet/IPv4/UDP frame of exactly `length` bytes."""
        f = (
            Ether(src=INNER_SRC_MAC, dst=INNER_DST_MAC)
            / IP(src=INNER_SRC_IP4, dst=INNER_DST_IP4)
            / UDP(sport=1234, dport=5000)
            / Raw(b"\x5a" * (length - 42))
        )
        f = Ether(bytes(f))
        self.assertEqual(len(bytes(f)), length)
        return f

    def tunnel_packet_raw(self, tun, payload, src=None, dst=None, underlay=None):
        """Underlay frame remote -> local whose outer payload is `payload`."""
        underlay = tun.underlay if underlay is None else underlay
        src = tun.dst if src is None else src
        dst = tun.src if dst is None else dst
        p = Ether(dst=underlay.local_mac, src=underlay.remote_mac) / self.outer_header(
            src, dst
        )
        if payload:
            p = p / Raw(payload)
        return p

    def tunnel_packet(self, tun, frame, header=ETHERIP_HEADER, **kwargs):
        """Underlay frame remote -> local carrying `header` + `frame`."""
        payload = bytes(etherip_header(header)) + bytes(frame)
        return self.tunnel_packet_raw(tun, payload, **kwargs)

    #
    # configuration helpers
    #
    def create_tunnel(
        self, underlay=None, host_index=0, outer_table_id=0, admin_up=True, **params
    ):
        underlay = self.pg1 if underlay is None else underlay
        host = underlay.remote_hosts[host_index]
        tun = VppEtherIPTunnel(
            self,
            self.local_addr(underlay),
            self.host_addr(host),
            outer_table_id=outer_table_id,
            **params,
        )
        tun.underlay = underlay
        tun.peer_mac = host.mac
        tun.add_vpp_config()
        if admin_up:
            tun.admin_up()
        return tun

    def xconnect(self, l2_if, tun):
        return VppL2Xconnect(self, l2_if, tun).add_vpp_config()

    def get_mtu(self, intf):
        for d in self.vapi.sw_interface_dump(sw_if_index=intf.sw_if_index):
            if d.sw_if_index == intf.sw_if_index:
                return list(d.mtu)
        self.fail("interface %s not found" % intf.name)

    def admin_flags(self, intf):
        """IF_STATUS_API_FLAG_ADMIN_UP bit of the interface (1 = up)."""
        for d in self.vapi.sw_interface_dump(sw_if_index=intf.sw_if_index):
            if d.sw_if_index == intf.sw_if_index:
                return int(d.flags) & 1
        self.fail("interface %d not found" % intf.sw_if_index)

    @staticmethod
    def lines_naming(out, name):
        """Lines of CLI output that contain `name` as a whole word."""
        pattern = re.compile(r"(?<![\w-])%s(?![\w-])" % re.escape(name))
        return [line for line in out.splitlines() if pattern.search(line)]

    def interface_name(self, sw_if_index):
        for i in self.vapi.sw_interface_dump(sw_if_index=sw_if_index):
            if i.sw_if_index == sw_if_index:
                return i.interface_name.rstrip(" \t\r\n\0")
        return None

    def find_tunnel_details(self, src, dst, outer_table_id=0):
        for d in self.vapi.etherip_tunnel_dump(sw_if_index=INDEX_INVALID):
            t = d.tunnel
            if (
                same_addr(t.src, src)
                and same_addr(t.dst, dst)
                and t.outer_table_id == outer_table_id
            ):
                return d
        return None

    #
    # verification helpers
    #
    def outer_payload(self, rx):
        """Bytes after the outer IP/IPv6 header, bounded by the length field."""
        if self.is_ip6:
            ip6 = rx[IPv6]
            return bytes(ip6)[40 : 40 + ip6.plen]
        ip4 = rx[IP]
        return bytes(ip4)[ip4.ihl * 4 : ip4.len]

    def verify_encap(
        self, rx, tun, frame, hop_limit=DEFAULT_HOP_LIMIT, dscp=0, df=False, ctx=""
    ):
        inner = bytes(frame)
        self.assertEqual(rx[Ether].src, tun.underlay.local_mac, ctx)
        self.assertEqual(rx[Ether].dst, tun.peer_mac, ctx)
        if self.is_ip6:
            self.assertEqual(rx[Ether].type, 0x86DD, ctx)
            ip6 = rx[IPv6]
            self.assertEqual(ip6.version, 6, ctx)
            self.assertTrue(same_addr(ip6.src, tun.src), ctx)
            self.assertTrue(same_addr(ip6.dst, tun.dst), ctx)
            self.assertEqual(ip6.nh, IP_PROTO_ETHERIP, ctx)
            self.assertEqual(ip6.hlim, hop_limit, "%s: outer hop limit" % ctx)
            self.assertEqual(ip6.tc, int(dscp) << 2, "%s: outer traffic class" % ctx)
            self.assertEqual(ip6.fl, 0, "%s: outer flow label" % ctx)
            self.assertEqual(ip6.plen, 2 + len(inner), "%s: payload length" % ctx)
        else:
            self.assertEqual(rx[Ether].type, 0x0800, ctx)
            ip4 = rx[IP]
            self.assertEqual(ip4.version, 4, ctx)
            self.assertTrue(same_addr(ip4.src, tun.src), ctx)
            self.assertTrue(same_addr(ip4.dst, tun.dst), ctx)
            self.assertEqual(ip4.proto, IP_PROTO_ETHERIP, ctx)
            self.assertEqual(ip4.ttl, hop_limit, "%s: outer TTL" % ctx)
            self.assertEqual(ip4.tos, int(dscp) << 2, "%s: outer TOS" % ctx)
            self.assertEqual(
                bool(int(ip4.flags) & 0x2), bool(df), "%s: outer DF bit" % ctx
            )
            self.assertEqual(int(ip4.flags) & 0x1, 0, "%s: outer MF bit" % ctx)
            self.assertEqual(ip4.frag, 0, "%s: outer fragment offset" % ctx)
            self.assertEqual(
                ip4.len, ip4.ihl * 4 + 2 + len(inner), "%s: total length" % ctx
            )
            self.assert_ip_checksum_valid(rx)
        payload = self.outer_payload(rx)
        self.assertEqual(payload[:2], ETHERIP_HEADER_BYTES, "%s: EtherIP hdr" % ctx)
        self.assertEqual(payload[2:], inner, "%s: inner frame" % ctx)

    def verify_decap(self, rxs, frames, ctx=""):
        self.assertEqual(len(rxs), len(frames), ctx)
        for rx, frame in zip(rxs, frames):
            self.assertEqual(bytes(rx), bytes(frame), "%s: decapsulated frame" % ctx)

    def assert_decap_diff(self, before, expected, ctx=""):
        diff = self.decap_diff(self.decap_node(), before)
        self.assertEqual(
            diff,
            expected,
            "%s: %s counter change %s, expected %s"
            % (ctx, self.decap_node(), diff, expected),
        )

    def send_and_expect_decap_drop(self, intf, pkts, counter, ctx=""):
        """Send pkts, expect no output anywhere and only `counter` to grow."""
        before = self.decap_snapshot(self.decap_node())
        self.send_and_assert_no_replies(intf, pkts, remark=ctx)
        self.assert_decap_diff(before, {counter: len(pkts)}, ctx)

    def send_and_expect_decap(self, tun, frames, l2_if, ctx="", **kwargs):
        """Send frames encapsulated towards tun, expect them on l2_if."""
        pkts = [self.tunnel_packet(tun, f, **kwargs) for f in frames]
        intf = kwargs.get("underlay") or tun.underlay
        before = self.decap_snapshot(self.decap_node())
        rxs = self.send_and_expect(intf, pkts, l2_if)
        self.verify_decap(rxs, frames, ctx)
        self.assert_decap_diff(before, {"DECAP": len(frames)}, ctx)
        return rxs

    def verify_details(self, details, tun, ctx=""):
        t = details.tunnel
        self.assertEqual(t.sw_if_index, tun.sw_if_index, ctx)
        self.assertTrue(same_addr(t.src, tun.src), "%s: src" % ctx)
        self.assertTrue(same_addr(t.dst, tun.dst), "%s: dst" % ctx)
        self.assertEqual(t.outer_table_id, tun.outer_table_id, "%s: table" % ctx)
        # details report the effective value: 64 for a tunnel created with 0
        self.assertEqual(
            t.hop_limit, tun.hop_limit or DEFAULT_HOP_LIMIT, "%s: hop_limit" % ctx
        )
        self.assertEqual(int(t.dscp), int(tun.dscp), "%s: dscp" % ctx)
        self.assertEqual(bool(t.set_df), bool(tun.set_df), "%s: set_df" % ctx)
        if tun.instance != INSTANCE_AUTO:
            self.assertEqual(t.instance, tun.instance, "%s: instance" % ctx)
        self.assertEqual(
            tun.name.rstrip(" \t\r\n\0"), "etherip%d" % t.instance, "%s: name" % ctx
        )

    def get_details_checked(self, tun):
        """Dump with the sw_if_index filter and expect exactly this tunnel."""
        ds = self.vapi.etherip_tunnel_dump(sw_if_index=tun.sw_if_index)
        self.assertEqual(len(ds), 1, "dump filtered by sw_if_index")
        self.assertEqual(ds[0].tunnel.sw_if_index, tun.sw_if_index)
        return ds[0]

    def verify_interface_properties(self, tun):
        ifs = [
            i
            for i in self.vapi.sw_interface_dump(sw_if_index=tun.sw_if_index)
            if i.sw_if_index == tun.sw_if_index
        ]
        self.assertEqual(len(ifs), 1)
        mac = str(ifs[0].l2_address).lower()
        self.assertTrue(mac.startswith("02:fe:"), "tunnel MAC %s" % mac)
        self.assertEqual(ifs[0].mtu[0], TUNNEL_SW_MTU, "tunnel L3 MTU")

    def reassemble_outer(self, rxs, tun):
        """Reassemble outer fragments, return the outer payload bytes."""
        frags = []
        for rx in rxs:
            self.assertEqual(rx[Ether].dst, tun.peer_mac)
            if self.is_ip6:
                ip6 = rx[IPv6]
                self.assertTrue(same_addr(ip6.src, tun.src))
                self.assertTrue(same_addr(ip6.dst, tun.dst))
                self.assertEqual(ip6.nh, IP6_NH_FRAGMENT)
                fh = rx[IPv6ExtHdrFragment]
                self.assertEqual(fh.nh, IP_PROTO_ETHERIP)
                data = bytes(ip6)[48 : 40 + ip6.plen]
                frags.append((fh.offset * 8, fh.m, data))
            else:
                ip4 = rx[IP]
                self.assertTrue(same_addr(ip4.src, tun.src))
                self.assertTrue(same_addr(ip4.dst, tun.dst))
                self.assertEqual(ip4.proto, IP_PROTO_ETHERIP)
                self.assertEqual(int(ip4.flags) & 0x2, 0, "DF must be clear")
                data = bytes(ip4)[ip4.ihl * 4 : ip4.len]
                frags.append((ip4.frag * 8, int(ip4.flags) & 0x1, data))
        frags.sort(key=lambda f: f[0])
        payload = b""
        for offset, more, data in frags:
            self.assertEqual(offset, len(payload), "fragment offsets not contiguous")
            payload += data
        self.assertEqual(frags[-1][1], 0, "last fragment has MF set")
        for f in frags[:-1]:
            self.assertEqual(f[1], 1, "non-last fragment has MF clear")
        return payload

    #
    # transmit
    #
    def test_encap(self):
        """EtherIP encap: outer header defaults and unmodified inner frame"""
        tun = self.create_tunnel()
        self.xconnect(self.pg0, tun)

        frames = self.make_frames(N_PKTS)
        rxs = self.send_and_expect(self.pg0, frames, self.pg1)
        for rx, frame in zip(rxs, frames):
            self.verify_encap(rx, tun, frame, ctx="default tunnel")

    def test_encap_counters(self):
        """EtherIP encap: tunnel TX interface counter and ENCAP counter"""
        tun = self.create_tunnel()
        self.xconnect(self.pg0, tun)

        tx_before = tun.get_tx_stats()
        encap_before = self.etherip_err(ENCAP_NODE, "ENCAP")
        frames = self.make_frames(N_PKTS)
        self.send_and_expect(self.pg0, frames, self.pg1)
        self.assertEqual(tun.get_tx_stats() - tx_before, N_PKTS, "tunnel TX")
        self.assertEqual(
            self.etherip_err(ENCAP_NODE, "ENCAP") - encap_before, N_PKTS, "ENCAP"
        )

    def tx_parameter_cases(self):
        d = VppEnum.vl_api_ip_dscp_t
        cases = [
            dict(hop_limit=255, dscp=d.IP_API_DSCP_EF),
            dict(hop_limit=200, dscp=d.IP_API_DSCP_AF31),
            dict(dscp=d.IP_API_DSCP_CS1),
        ]
        if not self.is_ip6:
            # IPv6 set_df: see test_set_df_hop_limit and test_df_fragmentation
            cases.append(dict(set_df=True))
            cases.append(dict(hop_limit=100, dscp=d.IP_API_DSCP_AF11, set_df=True))
        # last: a TTL decrement on the way out would drop this one entirely
        cases.append(dict(hop_limit=1))
        return cases

    def test_tx_parameters(self):
        """EtherIP encap: hop_limit, dscp and set_df change the outer header"""
        for i, params in enumerate(self.tx_parameter_cases()):
            ctx = "params %s" % params
            tun = self.create_tunnel(host_index=1 + i, **params)
            self.verify_details(self.get_details_checked(tun), tun, ctx)
            xc = self.xconnect(self.pg0, tun)

            frames = self.make_frames(N_ERR, start=i * N_ERR)
            rxs = self.send_and_expect(self.pg0, frames, self.pg1)
            for rx, frame in zip(rxs, frames):
                self.verify_encap(
                    rx,
                    tun,
                    frame,
                    hop_limit=params.get("hop_limit") or DEFAULT_HOP_LIMIT,
                    dscp=params.get("dscp", 0),
                    df=params.get("set_df", False),
                    ctx=ctx,
                )
            xc.remove_vpp_config()

    def test_df_fragmentation(self):
        """EtherIP encap: oversized outer packets fragmented only without set_df"""
        tun_frag = self.create_tunnel(host_index=1)
        tun_df = self.create_tunnel(host_index=2, set_df=True)
        # 1400 + 2 + outer header > 1280; IPv6 only checks MTU >= 1280
        frame = self.make_frame_of_len(1400)

        saved_mtu = self.get_mtu(self.pg1)
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [1280, 0, 0, 0])
        try:
            xc = self.xconnect(self.pg0, tun_frag)
            rxs = self.send_and_expect(self.pg0, [frame], self.pg1, n_rx=2)
            # fragment TTL / hop limit is not checked: ip4-frag / ip6-frag do
            # not carry LOCALLY_ORIGINATED over, so it is hop_limit - 1
            payload = self.reassemble_outer(rxs, tun_frag)
            self.assertEqual(payload, ETHERIP_HEADER_BYTES + bytes(frame))
            xc.remove_vpp_config()

            # set_df: IPv4 sets DF, IPv6 does not mark the packet locally
            # originated -> no fragmentation, nothing leaves the underlay
            xc = self.xconnect(self.pg0, tun_df)
            self.send_and_assert_no_replies(self.pg0, [frame], remark="set_df")
            xc.remove_vpp_config()
        finally:
            self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, saved_mtu)

    #
    # receive
    #
    def test_decap(self):
        """EtherIP decap: inner frame unchanged, DECAP and tunnel RX counters"""
        tun = self.create_tunnel()
        self.xconnect(self.pg0, tun)

        rx_before = tun.get_rx_stats()
        frames = self.make_frames(N_PKTS)
        self.send_and_expect_decap(tun, frames, self.pg0, ctx="decap")
        self.assertEqual(tun.get_rx_stats() - rx_before, N_PKTS, "tunnel RX")

    def test_rx_too_short(self):
        """EtherIP decap: less than 2 + 14 bytes after outer header -> TOO_SHORT"""
        tun = self.create_tunnel()
        self.xconnect(self.pg0, tun)
        self.send_and_expect_decap(tun, self.make_frames(1), self.pg0, ctx="control")

        cases = [
            ("empty payload", b""),
            ("1 byte", b"\x30"),
            ("header only", ETHERIP_HEADER_BYTES),
            ("header + 13 byte frame", ETHERIP_HEADER_BYTES + bytes(13)),
            # length is checked before the header
            ("bad header + 13 byte frame", b"\x03\x00" + bytes(13)),
        ]
        for ctx, payload in cases:
            pkts = [self.tunnel_packet_raw(tun, payload) for _ in range(N_ERR)]
            self.send_and_expect_decap_drop(self.pg1, pkts, "TOO_SHORT", ctx)

        # length is checked before the tunnel lookup
        src = self.host_addr(self.pg1.remote_hosts[7])
        pkts = [
            self.tunnel_packet_raw(tun, ETHERIP_HEADER_BYTES + bytes(13), src=src)
            for _ in range(N_ERR)
        ]
        self.send_and_expect_decap_drop(self.pg1, pkts, "TOO_SHORT", "unknown src")

    def test_rx_bad_header(self):
        """EtherIP decap: header other than 0x3000 -> BAD_HEADER"""
        tun = self.create_tunnel()
        self.xconnect(self.pg0, tun)
        frame = self.make_frames(1)[0]
        self.send_and_expect_decap(tun, [frame], self.pg0, ctx="control")

        # 0x0300: pre-RFC byte order, 0x3100 / 0x3010 / 0x3001: reserved != 0,
        # 0x2000 / 0x4000: version != 3
        for value in (0x0300, 0x3100, 0x3010, 0x3001, 0x2000, 0x4000):
            ctx = "header 0x%04x" % value
            # self-check of the test's own header encoding
            self.assertEqual(bytes(etherip_header(value)), value.to_bytes(2, "big"))
            pkts = [self.tunnel_packet(tun, frame, header=value)] * N_ERR
            self.send_and_expect_decap_drop(self.pg1, pkts, "BAD_HEADER", ctx)

        # the header is checked before the tunnel lookup
        src = self.host_addr(self.pg1.remote_hosts[7])
        pkts = [self.tunnel_packet(tun, frame, header=0x0300, src=src)] * N_ERR
        self.send_and_expect_decap_drop(self.pg1, pkts, "BAD_HEADER", "unknown src")

        self.send_and_expect_decap(tun, [frame], self.pg0, ctx="after bad headers")

    def test_rx_no_such_tunnel(self):
        """EtherIP decap: outer src not matching a tunnel -> NO_SUCH_TUNNEL"""
        tun = self.create_tunnel()
        self.xconnect(self.pg0, tun)
        frames = self.make_frames(N_ERR)

        src = self.host_addr(self.pg1.remote_hosts[7])
        pkts = [self.tunnel_packet(tun, f, src=src) for f in frames]
        self.send_and_expect_decap_drop(self.pg1, pkts, "NO_SUCH_TUNNEL", "src")

        self.send_and_expect_decap(tun, frames, self.pg0, ctx="matching src")

    def test_rx_tunnel_admin_down(self):
        """EtherIP decap: tunnel admin down -> TUNNEL_DOWN"""
        tun = self.create_tunnel(admin_up=False)
        self.xconnect(self.pg0, tun)
        frames = self.make_frames(N_ERR)
        pkts = [self.tunnel_packet(tun, f) for f in frames]

        self.send_and_expect_decap_drop(self.pg1, pkts, "TUNNEL_DOWN", "down")

        # the header is checked before the admin state
        bad = [self.tunnel_packet(tun, f, header=0x0300) for f in frames]
        self.send_and_expect_decap_drop(self.pg1, bad, "BAD_HEADER", "down, bad hdr")

        tun.admin_up()
        self.send_and_expect_decap(tun, frames, self.pg0, ctx="admin up")

        tun.admin_down()
        self.send_and_expect_decap_drop(self.pg1, pkts, "TUNNEL_DOWN", "down again")

    def test_small_frames(self):
        """EtherIP: inner frames shorter than 60 bytes are not padded"""
        tun = self.create_tunnel()
        self.xconnect(self.pg0, tun)

        arp = Ether(
            bytes(
                Ether(dst="ff:ff:ff:ff:ff:ff", src=INNER_SRC_MAC)
                / ARP(
                    op="who-has",
                    hwsrc=INNER_SRC_MAC,
                    psrc=INNER_SRC_IP4,
                    pdst=INNER_DST_IP4,
                )
            )
        )
        self.assertEqual(len(bytes(arp)), 42)

        rxs = self.send_and_expect(self.pg0, [arp] * N_ERR, self.pg1)
        for rx in rxs:
            self.verify_encap(rx, tun, arp, ctx="42 byte ARP")
        self.send_and_expect_decap(tun, [arp] * N_ERR, self.pg0, ctx="42 byte ARP")

        # 14 bytes (Ethernet header only) is the shortest accepted frame
        hdr_only = Ether(
            bytes(Ether(dst=INNER_DST_MAC, src=INNER_SRC_MAC, type=0x88B5))
        )
        self.assertEqual(len(bytes(hdr_only)), 14)
        self.send_and_expect_decap(tun, [hdr_only] * N_ERR, self.pg0, ctx="14 bytes")

    def test_outer_table(self):
        """EtherIP: non-default outer FIB, receive key includes the FIB"""
        tun = self.create_tunnel(underlay=self.pg2, outer_table_id=1)
        self.xconnect(self.pg0, tun)
        frames = self.make_frames(N_ERR)

        rxs = self.send_and_expect(self.pg0, frames, self.pg2)
        for rx, frame in zip(rxs, frames):
            self.verify_encap(rx, tun, frame, ctx="outer table 1")
        self.send_and_expect_decap(tun, frames, self.pg0, ctx="outer table 1")

        # make the same local address exist in table 0 (on pg1); the same
        # src/dst arriving in table 0 must not match the table 1 tunnel
        prefix = self.local_prefix(self.pg2)
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg1.sw_if_index, prefix=prefix, is_add=1
        )
        try:
            pkts0 = [self.tunnel_packet(tun, f, underlay=self.pg1) for f in frames]
            self.send_and_expect_decap_drop(
                self.pg1, pkts0, "NO_SUCH_TUNNEL", "same src/dst in table 0"
            )

            # a second tunnel with the same src/dst in table 0 is accepted and
            # each FIB delivers to its own tunnel
            twin = VppEtherIPTunnel(self, tun.src, tun.dst, outer_table_id=0)
            twin.underlay = self.pg1
            twin.peer_mac = self.pg1.remote_mac
            twin.add_vpp_config()
            twin.admin_up()
            twin_xc = self.xconnect(self.pg3, twin)

            rxs = self.send_and_expect(
                self.pg1, pkts0, self.pg3, assert_nothing_captured=[self.pg0]
            )
            self.verify_decap(rxs, frames, "table 0 twin")
            pkts1 = [self.tunnel_packet(tun, f) for f in frames]
            rxs = self.send_and_expect(
                self.pg2, pkts1, self.pg0, assert_nothing_captured=[self.pg3]
            )
            self.verify_decap(rxs, frames, "table 1 tunnel")

            twin_xc.remove_vpp_config()
            twin.remove_vpp_config()
        finally:
            self.vapi.sw_interface_add_del_address(
                sw_if_index=self.pg1.sw_if_index, prefix=prefix, is_add=0
            )

    def test_rx_link_padding(self):
        """EtherIP decap: link layer padding after the outer packet is dropped"""
        tun = self.create_tunnel()
        self.xconnect(self.pg0, tun)

        hdr_only = Ether(
            bytes(Ether(dst=INNER_DST_MAC, src=INNER_SRC_MAC, type=0x88B5))
        )
        arp = Ether(
            bytes(
                Ether(dst="ff:ff:ff:ff:ff:ff", src=INNER_SRC_MAC)
                / ARP(op="who-has", psrc=INNER_SRC_IP4, pdst=INNER_DST_IP4)
            )
        )
        cases = [
            # (context, inner frame, bytes appended after the outer packet)
            ("14 byte frame + 10 pad", hdr_only, 10),
            ("42 byte ARP + 18 pad", arp, 18),
            ("60 byte frame + 32 pad", self.make_frames(1)[0], 32),
        ]
        for ctx, frame, pad in cases:
            raw = bytes(self.tunnel_packet(tun, frame))
            padded = Ether(raw + b"\xee" * pad)
            # the outer length field excludes the padding
            self.assertEqual(len(bytes(padded)), len(raw) + pad, ctx)
            before = self.decap_snapshot(self.decap_node())
            rxs = self.send_and_expect(self.pg1, [padded] * N_ERR, self.pg0)
            self.verify_decap(rxs, [frame] * N_ERR, ctx)
            self.assert_decap_diff(before, {"DECAP": N_ERR}, ctx)

    def make_l2_frames(self, src_mac, dst_mac, count):
        frames = []
        for i in range(count):
            f = (
                Ether(src=src_mac, dst=dst_mac)
                / IP(src=INNER_SRC_IP4, dst=INNER_DST_IP4)
                / UDP(sport=2000 + i, dport=5000)
                / Raw(b"\xbd" * (40 + i))
            )
            frames.append(Ether(bytes(f)))
        return frames

    def test_bridge_domain(self):
        """EtherIP: tunnel in a bridge domain (flood, learning, delete member)"""
        tun = self.create_tunnel()
        bd = VppBridgeDomain(self, BD_ID, arp_term=0).add_vpp_config()
        for itf in (self.pg0, self.pg3, tun):
            VppBridgeDomainPort(self, bd, itf).add_vpp_config()

        mac_a = INNER_SRC_MAC  # host behind pg0
        mac_b = REMOTE_HOST_MAC  # host behind the remote tunnel endpoint
        to_b = self.make_l2_frames(mac_a, mac_b, N_ERR)
        to_a = self.make_l2_frames(mac_b, mac_a, N_ERR)

        # unknown unicast from pg0 is flooded to pg3 and to the tunnel
        caps = self.send_and_expect_multi(
            [Send(self.pg0, to_b)],
            [Expect(self.pg1, N_ERR), Expect(self.pg3, N_ERR)],
        )
        for rx, frame in zip(caps[0].packets, to_b):
            self.verify_encap(rx, tun, frame, ctx="BD flood to tunnel")
        self.verify_decap(caps[1].packets, to_b, "BD flood to pg3")

        # mac_a was learned on pg0: tunnel -> mac_a goes to pg0 only
        pkts = [self.tunnel_packet(tun, f) for f in to_a]
        rxs = self.send_and_expect(
            self.pg1, pkts, self.pg0, assert_nothing_captured=[self.pg3]
        )
        self.verify_decap(rxs, to_a, "BD tunnel -> learned mac_a")

        # mac_b was learned on the tunnel: pg0 -> mac_b goes to the tunnel only
        rxs = self.send_and_expect(
            self.pg0, to_b, self.pg1, assert_nothing_captured=[self.pg3]
        )
        for rx, frame in zip(rxs, to_b):
            self.verify_encap(rx, tun, frame, ctx="BD unicast to tunnel")
        self.assertTrue(find_l2_fib_entry(self, BD_ID, mac_a, self.pg0.sw_if_index))
        self.assertTrue(find_l2_fib_entry(self, BD_ID, mac_b, tun.sw_if_index))

        # delete the tunnel while it is still a bridge domain member
        tun_sw_if_index = tun.sw_if_index
        tun.remove_vpp_config()
        self.assertFalse(find_bridge_domain_port(self, BD_ID, tun_sw_if_index))
        # frames for the (previously learned) mac_b must not reach the
        # underlay and must not break VPP
        self.pg_send(self.pg0, to_b)
        self.pg1.assert_nothing_captured(remark="tunnel deleted")
        # the remaining members still forward
        bcast = self.make_l2_frames(mac_a, "ff:ff:ff:ff:ff:ff", N_ERR)
        rxs = self.send_and_expect(
            self.pg0, bcast, self.pg3, assert_nothing_captured=[self.pg1]
        )
        self.verify_decap(rxs, bcast, "BD after tunnel delete")

    def test_delete_xconnected_tunnel(self):
        """EtherIP: deleting an x-connected tunnel returns the peer to L3 mode"""
        tun = self.create_tunnel()
        xc = self.xconnect(self.pg0, tun)
        self.assertTrue(xc.query_vpp_config())
        mode = self.vapi.cli("show mode %s" % self.pg0.name).strip()
        self.assertTrue(mode.startswith("l2 xconnect"), mode)

        tun_sw_if_index = tun.sw_if_index
        tun.remove_vpp_config()

        pairs = [
            (x.rx_sw_if_index, x.tx_sw_if_index) for x in self.vapi.l2_xconnect_dump()
        ]
        left = [p for p in pairs if self.pg0.sw_if_index in p or tun_sw_if_index in p]
        self.assertEqual(left, [], "l2 xconnect entries after tunnel delete")
        mode = self.vapi.cli("show mode %s" % self.pg0.name).strip()
        self.assertTrue(mode.startswith("l3 "), mode)
        # pg0 is an L3 interface without address now: nothing is forwarded
        self.send_and_assert_no_replies(self.pg0, self.make_frames(N_ERR))

    def test_tx_admin_down(self):
        """EtherIP encap: admin down tunnel sends nothing, TX / ENCAP unchanged"""
        tun = self.create_tunnel(admin_up=False)
        self.xconnect(self.pg0, tun)
        frames = self.make_frames(N_ERR)

        tx_before = tun.get_tx_stats()
        encap_before = self.etherip_err(ENCAP_NODE, "ENCAP")
        self.send_and_assert_no_replies(self.pg0, frames, remark="admin down")
        self.assertEqual(tun.get_tx_stats(), tx_before, "tunnel TX while down")
        self.assertEqual(
            self.etherip_err(ENCAP_NODE, "ENCAP"), encap_before, "ENCAP while down"
        )

        tun.admin_up()
        rxs = self.send_and_expect(self.pg0, frames, self.pg1)
        for rx, frame in zip(rxs, frames):
            self.verify_encap(rx, tun, frame, ctx="admin up")
        self.assertEqual(tun.get_tx_stats() - tx_before, N_ERR, "tunnel TX up")
        self.assertEqual(
            self.etherip_err(ENCAP_NODE, "ENCAP") - encap_before, N_ERR, "ENCAP up"
        )

    def test_tx_admin_down_tx_down_counter(self):
        """EtherIP encap: optional TX_DOWN counts frames for an admin down tunnel"""
        if self.etherip_err_or_none(ENCAP_NODE, "TX_DOWN") is None:
            self.skipTest(
                "optional TX_DOWN counter (spec v0.4 7.1.4) is not implemented, "
                "tried %s" % (self.etherip_err_paths(ENCAP_NODE, "TX_DOWN"),)
            )
        tun = self.create_tunnel(admin_up=False)
        self.xconnect(self.pg0, tun)
        frames = self.make_frames(N_ERR)

        before = self.etherip_err(ENCAP_NODE, "TX_DOWN")
        self.send_and_assert_no_replies(self.pg0, frames, remark="admin down")
        self.assertEqual(self.etherip_err(ENCAP_NODE, "TX_DOWN") - before, N_ERR)

        tun.admin_up()
        self.send_and_expect(self.pg0, frames, self.pg1)
        self.assertEqual(
            self.etherip_err(ENCAP_NODE, "TX_DOWN") - before, N_ERR, "TX_DOWN up"
        )

    #
    # allow switch
    #
    def test_allow_default_off(self):
        """EtherIP allow switch: off right after VPP start"""
        if self.initial_allow_error is not None:
            self.fail("etherip_get_allow failed: %r" % (self.initial_allow_error,))
        self.assertFalse(self.initial_allow)

    def test_allow_policy(self):
        """EtherIP allow switch: off drops as POLICY_DROP, transmit unaffected"""
        tun = self.create_tunnel()
        self.xconnect(self.pg0, tun)
        frames = self.make_frames(N_ERR)
        pkts = [self.tunnel_packet(tun, f) for f in frames]

        self.vapi.etherip_set_allow(enable=False)
        self.assertFalse(self.vapi.etherip_get_allow().enable)
        rx_before = tun.get_rx_stats()
        self.send_and_expect_decap_drop(self.pg1, pkts, "POLICY_DROP", "allow off")
        self.assertEqual(tun.get_rx_stats(), rx_before, "tunnel RX while off")

        # transmit is not restricted by the allow switch
        rxs = self.send_and_expect(self.pg0, frames, self.pg1)
        for rx, frame in zip(rxs, frames):
            self.verify_encap(rx, tun, frame, ctx="allow off")

        self.vapi.etherip_set_allow(enable=True)
        self.assertTrue(self.vapi.etherip_get_allow().enable)
        self.send_and_expect_decap(tun, frames, self.pg0, ctx="allow on")

        self.vapi.etherip_set_allow(enable=False)
        self.assertFalse(self.vapi.etherip_get_allow().enable)
        self.send_and_expect_decap_drop(self.pg1, pkts, "POLICY_DROP", "off again")

    def test_allow_policy_precedes_other_checks(self):
        """EtherIP allow switch: off is checked before all other drop reasons"""
        tun = self.create_tunnel()
        self.xconnect(self.pg0, tun)
        down = self.create_tunnel(host_index=1, admin_up=False)
        frame = self.make_frames(1)[0]
        unknown_src = self.host_addr(self.pg1.remote_hosts[7])

        self.vapi.etherip_set_allow(enable=False)
        cases = [
            ("too short", self.tunnel_packet_raw(tun, b"\x30")),
            ("bad header", self.tunnel_packet(tun, frame, header=0x0300)),
            ("unknown src", self.tunnel_packet(tun, frame, src=unknown_src)),
            ("admin down tunnel", self.tunnel_packet(down, frame)),
        ]
        for ctx, pkt in cases:
            self.send_and_expect_decap_drop(self.pg1, [pkt] * N_ERR, "POLICY_DROP", ctx)

    def test_allow_cli(self):
        """EtherIP allow switch: set / show etherip allow CLI"""
        self.vapi.cli("set etherip allow off")
        self.assertFalse(self.vapi.etherip_get_allow().enable)
        self.assertIn("allow: off", self.vapi.cli("show etherip allow"))

        self.vapi.cli("set etherip allow on")
        self.assertTrue(self.vapi.etherip_get_allow().enable)
        self.assertIn("allow: on", self.vapi.cli("show etherip allow"))

        # API changes are visible in the CLI
        self.vapi.etherip_set_allow(enable=False)
        self.assertIn("allow: off", self.vapi.cli("show etherip allow"))
        self.vapi.etherip_set_allow(enable=True)
        self.assertIn("allow: on", self.vapi.cli("show etherip allow"))

    #
    # control plane
    #
    def test_api_add_del_dump(self):
        """EtherIP API: add, duplicate key, dump fields, delete, re-create"""
        d = VppEnum.vl_api_ip_dscp_t
        src = self.local_addr(self.pg1)
        dst1 = self.host_addr(self.pg1.remote_hosts[1])
        dst2 = self.host_addr(self.pg1.remote_hosts[2])
        dst3 = self.host_addr(self.pg1.remote_hosts[3])

        # precondition for the instance numbers checked below
        self.assertEqual(self.vapi.etherip_tunnel_dump(sw_if_index=INDEX_INVALID), [])

        t1 = VppEtherIPTunnel(self, src, dst1).add_vpp_config()
        d1 = self.get_details_checked(t1)
        self.verify_details(d1, t1, "t1")
        self.verify_interface_properties(t1)
        # automatic instance = lowest unused number
        self.assertEqual(d1.tunnel.instance, 0, "t1 instance")
        self.assertEqual(self.admin_flags(t1), 0, "admin state right after create")

        # same (outer_table_id, src, dst) is rejected, whatever the other fields
        for params in ({}, dict(hop_limit=10, dscp=d.IP_API_DSCP_EF, set_df=True)):
            with self.vapi.assert_negative_api_retval():
                self.vapi.etherip_tunnel_add_del(
                    is_add=True, tunnel=etherip_tunnel_args(src, dst1, **params)
                )

        # same src/dst in another outer table is a different key
        t1_tbl1 = VppEtherIPTunnel(self, src, dst1, outer_table_id=1).add_vpp_config()
        d1_tbl1 = self.get_details_checked(t1_tbl1)
        self.verify_details(d1_tbl1, t1_tbl1, "t1 tbl 1")
        self.assertEqual(d1_tbl1.tunnel.instance, 1, "t1 tbl 1 instance")

        # explicit instance and parameters
        t2 = VppEtherIPTunnel(
            self,
            src,
            dst2,
            instance=17,
            hop_limit=99,
            dscp=d.IP_API_DSCP_AF31,
            set_df=True,
        ).add_vpp_config()
        self.assertEqual(t2.name.rstrip(" \t\r\n\0"), "etherip17")
        self.verify_details(self.get_details_checked(t2), t2, "t2")

        # instance already used by t2
        with self.vapi.assert_negative_api_retval():
            self.vapi.etherip_tunnel_add_del(
                is_add=True, tunnel=etherip_tunnel_args(src, dst3, instance=17)
            )

        # src and dst of different address families
        other = self.other_af_host_addr(self.pg1.remote_hosts[3])
        with self.vapi.assert_negative_api_retval():
            self.vapi.etherip_tunnel_add_del(
                is_add=True, tunnel=etherip_tunnel_args(src, other)
            )

        # dump all
        dump = {
            e.tunnel.sw_if_index: e
            for e in self.vapi.etherip_tunnel_dump(sw_if_index=INDEX_INVALID)
        }
        self.assertEqual(len(dump), 3, "number of tunnels in dump")
        for t, ctx in ((t1, "t1"), (t1_tbl1, "t1 tbl 1"), (t2, "t2")):
            self.assertIn(t.sw_if_index, dump, ctx)
            self.verify_details(dump[t.sw_if_index], t, "dump all " + ctx)

        # delete, delete again, re-create
        t1.remove_vpp_config()
        self.assertFalse(t1.query_vpp_config())
        dump = self.vapi.etherip_tunnel_dump(sw_if_index=INDEX_INVALID)
        self.assertNotIn(t1.sw_if_index, [e.tunnel.sw_if_index for e in dump])
        self.assertEqual(len(dump), 2)

        with self.vapi.assert_negative_api_retval():
            self.vapi.etherip_tunnel_add_del(
                is_add=False, tunnel=etherip_tunnel_args(src, dst1)
            )

        t1b = VppEtherIPTunnel(self, src, dst1).add_vpp_config()
        d1b = self.get_details_checked(t1b)
        self.verify_details(d1b, t1b, "t1 re-created")
        # instance 0 was freed by the delete and is the lowest unused again
        self.assertEqual(d1b.tunnel.instance, 0, "re-created t1 instance")

    def test_api_invalid_endpoints(self):
        """EtherIP API: multicast / zero / equal endpoints and dscp > 63 rejected"""
        src = self.local_addr(self.pg1)
        dst = self.host_addr(self.pg1.remote_hosts[1])
        if self.is_ip6:
            mcast_src, mcast_dst, zero = "ff02::5", "ff0e::1", "::"
        else:
            mcast_src, mcast_dst, zero = "224.0.0.5", "239.255.0.1", "0.0.0.0"

        cases = [
            ("multicast src", etherip_tunnel_args(mcast_src, dst)),
            ("multicast dst", etherip_tunnel_args(src, mcast_dst)),
            ("zero src", etherip_tunnel_args(zero, dst)),
            ("zero dst", etherip_tunnel_args(src, zero)),
            ("src == dst", etherip_tunnel_args(src, src)),
            ("dscp 64", etherip_tunnel_args(src, dst, dscp=64)),
            ("dscp 255", etherip_tunnel_args(src, dst, dscp=255)),
        ]
        for ctx, args in cases:
            with self.vapi.assert_negative_api_retval():
                self.vapi.etherip_tunnel_add_del(is_add=True, tunnel=args)
            self.assertEqual(
                self.vapi.etherip_tunnel_dump(sw_if_index=INDEX_INVALID),
                [],
                "%s: rejected add left a tunnel behind" % ctx,
            )

        # the same src/dst with valid parameters is accepted
        t = VppEtherIPTunnel(self, src, dst).add_vpp_config()
        self.assertTrue(t.query_vpp_config())

    def test_cli_create_show_delete(self):
        """EtherIP CLI: create / show / delete etherip tunnel"""
        src = self.local_addr(self.pg1)
        dst = self.host_addr(self.pg1.remote_hosts[4])
        src1 = self.local_addr(self.pg2)
        dst1 = self.host_addr(self.pg2.remote_hosts[0])
        base = "create etherip tunnel src %s dst %s" % (src, dst)
        base1 = "create etherip tunnel src %s dst %s outer-table-id 1" % (src1, dst1)

        self.vapi.cli("%s instance 7 hop-limit 33 set-df" % base)
        e = self.find_tunnel_details(src, dst)
        self.assertIsNotNone(e, "tunnel created by CLI not in dump")
        self.assertEqual(e.tunnel.instance, 7)
        self.assertEqual(e.tunnel.outer_table_id, 0)
        self.assertEqual(e.tunnel.hop_limit, 33)
        self.assertEqual(int(e.tunnel.dscp), 0)
        self.assertTrue(e.tunnel.set_df)
        self.assertEqual(self.interface_name(e.tunnel.sw_if_index), "etherip7")

        # duplicate key
        with self.assertRaises((CliFailedCommandError, CliSyntaxError)):
            self.vapi.cli(base)

        self.vapi.cli(base1)
        e1 = self.find_tunnel_details(src1, dst1, outer_table_id=1)
        self.assertIsNotNone(e1, "tunnel with outer-table-id 1 not in dump")
        name1 = self.interface_name(e1.tunnel.sw_if_index)
        self.assertEqual(name1, "etherip%d" % e1.tunnel.instance)

        # one line per tunnel: interface name, src/dst, table, hop-limit, ...
        out = self.vapi.cli("show etherip tunnel")
        for name, s, d in (("etherip7", src, dst), (name1, src1, dst1)):
            lines = self.lines_naming(out, name)
            self.assertEqual(len(lines), 1, "show etherip tunnel: %s\n%s" % (name, out))
            self.assertIn(s, lines[0], "src in line of %s" % name)
            self.assertIn(d, lines[0], "dst in line of %s" % name)
        out = self.vapi.cli("show etherip tunnel etherip7")
        self.assertEqual(len(self.lines_naming(out, "etherip7")), 1, out)
        self.assertEqual(self.lines_naming(out, name1), [], out)

        self.vapi.cli("%s del" % base)
        self.vapi.cli("%s del" % base1)
        self.assertIsNone(self.find_tunnel_details(src, dst))
        self.assertIsNone(self.find_tunnel_details(src1, dst1, outer_table_id=1))

    def test_cli_dscp(self):
        """EtherIP CLI: dscp as code point name and as number 0-63"""
        d = VppEnum.vl_api_ip_dscp_t
        src = self.local_addr(self.pg1)
        cases = (
            # (remote host, CLI dscp argument, expected value)
            (5, "AF31", int(d.IP_API_DSCP_AF31)),
            # numeric form; EF (46) so that the dump decodes to an enum member
            (6, "46", int(d.IP_API_DSCP_EF)),
        )
        for host_index, arg, value in cases:
            dst = self.host_addr(self.pg1.remote_hosts[host_index])
            base = "create etherip tunnel src %s dst %s" % (src, dst)
            self.vapi.cli("%s dscp %s" % (base, arg))
            e = self.find_tunnel_details(src, dst)
            self.assertIsNotNone(e, "dscp %s" % arg)
            self.assertEqual(int(e.tunnel.dscp), value, "dscp %s" % arg)
            self.vapi.cli("%s del" % base)
            self.assertIsNone(self.find_tunnel_details(src, dst))

        # out of range
        dst = self.host_addr(self.pg1.remote_hosts[7])
        with self.assertRaises((CliFailedCommandError, CliSyntaxError)):
            self.vapi.cli("create etherip tunnel src %s dst %s dscp 64" % (src, dst))
        self.assertIsNone(self.find_tunnel_details(src, dst))


@unittest.skipIf("etherip" in config.excluded_plugins, "Exclude EtherIP plugin tests")
class TestEtherIP4(EtherIPTestMixin, VppTestCase):
    """EtherIP over IPv4 Test Case"""

    is_ip6 = False

    def test_ip4_identification(self):
        """EtherIP4 encap without set_df: outer IPv4 IDs differ per packet"""
        tun = self.create_tunnel()
        self.xconnect(self.pg0, tun)
        frames = self.make_frames(10)
        rxs = self.send_and_expect(self.pg0, frames, self.pg1)
        for rx, frame in zip(rxs, frames):
            # the header checksum must cover the ID written by the fixup
            self.verify_encap(rx, tun, frame, ctx="IPv4 ID")
        ids = [rx[IP].id for rx in rxs]
        self.assertEqual(len(set(ids)), len(ids), "outer IPv4 IDs %s" % ids)

    def test_rx_ip4_options(self):
        """EtherIP4 decap: outer IPv4 header with options (ihl > 5)"""
        tun = self.create_tunnel()
        self.xconnect(self.pg0, tun)
        frames = self.make_frames(N_ERR)
        self.send_and_expect_decap(tun, frames, self.pg0, ctx="control")

        variants = [
            ("4 x NOP", [IPOption_NOP()] * 4),
            ("Router Alert", [IPOption_Router_Alert()]),
        ]
        for ctx, options in variants:
            pkts = [
                Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac)
                / IP(
                    src=tun.dst,
                    dst=tun.src,
                    proto=IP_PROTO_ETHERIP,
                    ttl=64,
                    options=options,
                )
                / Raw(ETHERIP_HEADER_BYTES + bytes(f))
                for f in frames
            ]
            self.assertEqual(Ether(bytes(pkts[0]))[IP].ihl, 6, ctx)

            before = self.decap_snapshot(self.decap_node())
            opt_before = self.ip4_options_counter()
            self.pg_send(self.pg1, pkts)
            diff = self.decap_diff(self.decap_node(), before)
            if not diff:
                # the packets never reached etherip4-input
                for i in self.pg_interfaces:
                    i.assert_nothing_captured(remark=ctx)
                opt = self.ip4_options_counter()
                self.skipTest(
                    "%s: ip4-input sends IPv4 packets with options to "
                    "ip4-options, which punts all of them except Router Alert "
                    "+ IGMP (src/vnet/ip/ip4_options.c), so they never reach "
                    "ip4-local / etherip4-input (/err/ip4-input/options "
                    "%s -> %s). Spec v0.4 7.2.2 cannot be verified on this VPP."
                    % (ctx, opt_before, opt)
                )
            self.assertEqual(diff, {"DECAP": len(frames)}, ctx)
            self.verify_decap(self.pg0.get_capture(len(frames)), frames, ctx)

    def ip4_options_counter(self):
        try:
            return int(self.statistics.get_err_counter("/err/ip4-input/options"))
        except KeyError:
            return None


@unittest.skipIf("etherip" in config.excluded_plugins, "Exclude EtherIP plugin tests")
class TestEtherIP6(EtherIPTestMixin, VppTestCase):
    """EtherIP over IPv6 Test Case"""

    is_ip6 = True

    def test_set_df_hop_limit(self):
        """EtherIP6 encap with set_df: wire hlim = hop_limit (255 -> 254)"""
        # spec v0.4 1 / 4.4: with set_df the buffer is not marked locally
        # originated, ip6-rewrite decrements the hop limit and the rewrite
        # holds min(hop_limit + 1, 255) to compensate
        cases = [
            # (hop_limit given to the API, hop limit expected on the wire)
            (0, DEFAULT_HOP_LIMIT),
            (1, 1),
            (200, 200),
            (255, 254),
        ]
        for i, (hop_limit, wire) in enumerate(cases):
            ctx = "set_df, hop_limit %d" % hop_limit
            tun = self.create_tunnel(host_index=1 + i, hop_limit=hop_limit, set_df=True)
            # dump reports the configured effective value, not the wire value
            self.verify_details(self.get_details_checked(tun), tun, ctx)
            xc = self.xconnect(self.pg0, tun)
            frames = self.make_frames(N_ERR, start=i * N_ERR)
            rxs = self.send_and_expect(self.pg0, frames, self.pg1)
            for rx, frame in zip(rxs, frames):
                self.verify_encap(rx, tun, frame, hop_limit=wire, ctx=ctx)
            xc.remove_vpp_config()


@unittest.skipIf("etherip" in config.excluded_plugins, "Exclude EtherIP plugin tests")
class TestEtherIPInputNodes(EtherIPCountersMixin, VppTestCase):
    """EtherIP input node registration Test Case"""

    @classmethod
    def setUpClass(cls):
        super(TestEtherIPInputNodes, cls).setUpClass()
        cls.create_pg_interfaces(range(1))

    @classmethod
    def tearDownClass(cls):
        super(TestEtherIPInputNodes, cls).tearDownClass()

    def setUp(self):
        super(TestEtherIPInputNodes, self).setUp()
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.disable_ipv6_ra()

    def tearDown(self):
        super(TestEtherIPInputNodes, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.unconfig_ip6()
                i.admin_down()

    def check_registration(self, is_ip6):
        frame = Ether(src=INNER_SRC_MAC, dst=INNER_DST_MAC) / Raw(bytes(46))
        if is_ip6:
            outer = IPv6(
                src=self.pg0.remote_ip6, dst=self.pg0.local_ip6, nh=IP_PROTO_ETHERIP
            )
            # ip6-local counts its errors against the ip6-input node
            local_err = "/err/ip6-input/unknown_protocol"
            node = "etherip6-input"
            tun_src, tun_dst = self.pg0.local_ip6, "2001:db8::2"
        else:
            outer = IP(
                src=self.pg0.remote_ip4, dst=self.pg0.local_ip4, proto=IP_PROTO_ETHERIP
            )
            local_err = "/err/ip4-local/unknown_protocol"
            node = "etherip4-input"
            tun_src, tun_dst = self.pg0.local_ip4, "198.51.100.2"
        pkt = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / outer
            / Raw(ETHERIP_HEADER_BYTES + bytes(frame))
        )

        def node_total():
            return sum(self.decap_snapshot(node).values())

        # no tunnel yet: protocol 97 is not registered
        unknown = self.statistics.get_err_counter(local_err)
        total = node_total()
        self.pg_send(self.pg0, [pkt])
        self.assertEqual(self.statistics.get_err_counter(local_err) - unknown, 1)
        self.assertEqual(node_total() - total, 0)

        # first tunnel of this AF registers protocol 97 with ipX-local
        tun = VppEtherIPTunnel(self, tun_src, tun_dst)
        tun.add_vpp_config()
        self.assertTrue(tun.query_vpp_config())

        unknown = self.statistics.get_err_counter(local_err)
        total = node_total()
        self.pg_send(self.pg0, [pkt])
        self.assertEqual(self.statistics.get_err_counter(local_err) - unknown, 0)
        # the packet is now counted by the EtherIP input node (whichever
        # counter: the allow switch is still at its default)
        self.assertEqual(node_total() - total, 1)

    def test_input_node_ip4(self):
        """EtherIP4 input node: protocol 97 registered by the first tunnel"""
        self.check_registration(is_ip6=False)

    def test_input_node_ip6(self):
        """EtherIP6 input node: next header 97 registered by the first tunnel"""
        self.check_registration(is_ip6=True)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
