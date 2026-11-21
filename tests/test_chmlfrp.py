"""ChmlFrp API 客户端的离线单元测试。"""

from __future__ import annotations

import sys
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine import chmlfrp


class PortRangeTests(unittest.TestCase):
    def test_parse_range(self) -> None:
        self.assertEqual(chmlfrp.port_range("30000-30010"), (30000, 30010))
        self.assertEqual(chmlfrp.port_range("30010~30000"), (30000, 30010))
        self.assertEqual(chmlfrp.port_range("25565"), (25565, 25565))

    def test_fallback_range(self) -> None:
        self.assertEqual(chmlfrp.port_range(""), chmlfrp.DEFAULT_PORT_RANGE)
        self.assertEqual(chmlfrp.port_range(None), chmlfrp.DEFAULT_PORT_RANGE)

    def test_pick_remote_port(self) -> None:
        self.assertEqual(chmlfrp.pick_remote_port({}, 12345), 12345)
        port = chmlfrp.pick_remote_port({"rport": "30000-30010"})
        self.assertTrue(30000 <= port <= 30010)
        port = chmlfrp.pick_remote_port({})
        self.assertTrue(1024 <= port <= 65535)
        with self.assertRaises(chmlfrp.ChmlFrpError):
            chmlfrp.pick_remote_port({}, 80)


class NameAndAddressTests(unittest.TestCase):
    def test_tunnel_name(self) -> None:
        self.assertEqual(chmlfrp.tunnel_name_for(25565), "AML-MC-25565")
        self.assertEqual(chmlfrp.normalize_tunnel_name("", 25565), "AML-MC-25565")
        self.assertEqual(chmlfrp.normalize_tunnel_name("我的 隧道", 25565), "我的-隧道")
        self.assertEqual(chmlfrp.normalize_tunnel_name("a b!", 25565), "a-b")

    def test_connect_address(self) -> None:
        self.assertEqual(
            chmlfrp.connect_address({"ip": "node.example.com"}, {"dorp": "11894"}),
            "node.example.com:11894",
        )
        self.assertEqual(
            chmlfrp.connect_address(
                {"ip": "node.example.com"}, {"dorp": "x.example.com:11894"}
            ),
            "x.example.com:11894",
        )
        self.assertEqual(chmlfrp.connect_address({}, {"dorp": ""}), "")


class SessionTests(unittest.TestCase):
    def test_expiry_normalization(self) -> None:
        self.assertEqual(chmlfrp.normalize_expiry(1700000000), 1700000000.0)
        self.assertEqual(chmlfrp.normalize_expiry("1700000000000"), 1700000000.0)
        self.assertEqual(chmlfrp.normalize_expiry(None), 0.0)

    def test_userinfo_uses_bearer(self) -> None:
        calls: list[dict] = []

        def fake_request(url, **kwargs):
            calls.append({"url": url, **kwargs})
            return 200, {"state": "success", "data": {"username": "aml-user"}}

        with mock.patch.object(chmlfrp.net, "request_json", side_effect=fake_request):
            info = chmlfrp.userinfo("access-1")
        self.assertEqual(info["username"], "aml-user")
        self.assertEqual(calls[0]["headers"]["Authorization"], "Bearer access-1")

    def test_refresh_session(self) -> None:
        payload = {
            "state": "success",
            "data": {
                "access_token": "new-access",
                "refresh_token": "new-refresh",
                "expires_at": 1700000000,
            },
        }
        with mock.patch.object(chmlfrp.net, "request_json", return_value=(200, payload)):
            result = chmlfrp.refresh_session("old-refresh")
        self.assertEqual(result["access_token"], "new-access")
        self.assertEqual(result["refresh_token"], "new-refresh")
        self.assertEqual(result["expires_at"], 1700000000.0)

    def test_refresh_requires_token(self) -> None:
        with self.assertRaises(chmlfrp.ChmlFrpError):
            chmlfrp.refresh_session("")


class SsoListenerTests(unittest.TestCase):
    def test_callback_roundtrip(self) -> None:
        listener = chmlfrp.SsoListener()
        try:
            html = urllib.request.urlopen(listener.return_url, timeout=10).read().decode()
            self.assertIn("ChmlFrp", html)
            url = listener.return_url + "token?access_token=a1&refresh_token=r1&expires_at=123"
            self.assertEqual(urllib.request.urlopen(url, timeout=10).read().decode(), "ok")
            params = listener.wait(3)
        finally:
            listener.close()
        self.assertEqual(params["access_token"], "a1")
        self.assertEqual(params["refresh_token"], "r1")

    def test_timeout(self) -> None:
        listener = chmlfrp.SsoListener()
        try:
            with self.assertRaises(chmlfrp.ChmlFrpError):
                listener.wait(0.1)
        finally:
            listener.close()


class NodeTests(unittest.TestCase):
    def test_available_nodes_filters_and_sorts(self) -> None:
        nodes = [
            {"name": "离线节点", "area": "中国北京"},
            {"name": "慢节点", "area": "中国上海"},
            {"name": "快节点", "area": "中国广州"},
            {"name": "VIP 节点", "area": "中国香港"},
        ]
        details = {
            "离线节点": {"state": "offline", "ip": "off.example.com", "port": 7000},
            "慢节点": {"state": "online", "ip": "slow.example.com", "port": 7000},
            "快节点": {"state": "online", "ip": "fast.example.com", "port": 7000},
        }

        def fake_detail(access: str, name: str, **_: object) -> dict:
            if name == "VIP 节点":
                raise chmlfrp.ChmlFrpError("非会员")
            return details[name]

        latencies = {"slow.example.com": 80, "fast.example.com": 12}

        def fake_latency(host: str, port: int, **_: object):
            return latencies.get(host)

        with mock.patch.object(chmlfrp, "list_nodes", return_value=nodes), \
                mock.patch.object(chmlfrp, "node_detail", side_effect=fake_detail), \
                mock.patch.object(chmlfrp, "tcp_latency", side_effect=fake_latency):
            result = chmlfrp.available_nodes("access")
        self.assertEqual([item["name"] for item in result], ["快节点", "慢节点"])
        self.assertEqual(result[0]["latency_ms"], 12)

    def test_available_nodes_empty(self) -> None:
        with mock.patch.object(chmlfrp, "list_nodes", return_value=[]):
            self.assertEqual(chmlfrp.available_nodes("access"), [])


class TunnelTests(unittest.TestCase):
    def test_create_when_missing(self) -> None:
        calls: list[tuple[str, dict]] = []

        def fake_call(path, **kwargs):
            calls.append((path, kwargs))
            return {"state": "success", "data": {"dorp": "30001"}}

        with mock.patch.object(chmlfrp, "list_tunnels", return_value=[]), \
                mock.patch.object(chmlfrp, "_call", side_effect=fake_call):
            tunnel = chmlfrp.create_or_update_tunnel(
                "access",
                "usertoken",
                name="AML-MC-25565",
                node="快节点",
                local_port=25565,
                remote_port=30001,
            )
        self.assertEqual(calls[0][0], "/create_tunnel")
        self.assertEqual(calls[0][1]["access"], "access")
        body = calls[0][1]["body"]
        self.assertEqual(body["token"], "usertoken")
        self.assertEqual(body["porttype"], "tcp")
        self.assertEqual(tunnel["dorp"], "30001")

    def test_update_when_exists(self) -> None:
        calls: list[tuple[str, dict]] = []

        def fake_call(path, **kwargs):
            calls.append((path, kwargs))
            return {"state": "success", "data": {}}

        existing = [{"id": 7, "name": "AML-MC-25565", "node": "旧节点"}]
        with mock.patch.object(chmlfrp, "list_tunnels", return_value=existing), \
                mock.patch.object(chmlfrp, "_call", side_effect=fake_call):
            tunnel = chmlfrp.create_or_update_tunnel(
                "access",
                "usertoken",
                name="AML-MC-25565",
                node="快节点",
                local_port=25566,
                remote_port=30002,
                encryption=False,
                compression=True,
            )
        self.assertEqual(calls[0][0], "/update_tunnel")
        body = calls[0][1]["body"]
        self.assertEqual(body["tunnelid"], 7)
        self.assertEqual(body["localport"], 25566)
        self.assertEqual(body["encryption"], "false")
        self.assertEqual(body["compression"], "true")
        self.assertEqual(tunnel["dorp"], "30002")

    def test_tunnel_config_requires_data(self) -> None:
        with mock.patch.object(
            chmlfrp, "_call", return_value={"state": "success", "data": ""}
        ):
            with self.assertRaises(chmlfrp.ChmlFrpError):
                chmlfrp.tunnel_config("access", "快节点", "AML-MC-25565")

    def test_tunnel_config_requests_toml(self) -> None:
        calls: list[tuple[str, dict]] = []

        def fake_call(path, **kwargs):
            calls.append((path, kwargs))
            return {"state": "success", "data": "serverAddr = \"x\"\n"}

        with mock.patch.object(chmlfrp, "_call", side_effect=fake_call):
            config = chmlfrp.tunnel_config("access", "快节点", "AML-MC-25565")
        params = calls[0][1]["params"]
        self.assertEqual(params["format"], "toml")
        self.assertEqual(params["protocol"], "tcp")
        self.assertEqual(params["tunnel_names"], "AML-MC-25565")
        self.assertTrue(config.endswith("\n"))

    def test_delete_tunnel_uses_query(self) -> None:
        calls: list[tuple[str, dict]] = []

        def fake_call(path, **kwargs):
            calls.append((path, kwargs))
            return {"state": "success"}

        with mock.patch.object(chmlfrp, "_call", side_effect=fake_call):
            self.assertTrue(chmlfrp.delete_tunnel("access", "42"))
        self.assertEqual(calls[0][0], "/delete_tunnel")
        self.assertEqual(calls[0][1]["params"]["tunnelid"], "42")


if __name__ == "__main__":
    unittest.main()
