"""ChmlFrp v2 API 客户端：SSO 登录、节点测速、隧道与 frpc 配置。

文档：https://docs.chmlfrp.net/API/v2/
ChmlFrp 已改为 SSO + Bearer 令牌：登录时在浏览器完成授权，回调里拿到
access_token / refresh_token，之后的接口都带 ``Authorization: Bearer``。
"""

from __future__ import annotations

import random
import re
import socket
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from . import net

API_BASE = "https://cf-v2.uapis.cn"
DEFAULT_SERVER_PORT = 7000
DEFAULT_LOCAL_IP = "127.0.0.1"
# 节点没有返回外网端口范围时使用的兜底区间。
DEFAULT_PORT_RANGE = (10000, 65000)

LOGIN_HTML = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>ChmlFrp 登录</title>
<style>body{font-family:system-ui,"Microsoft YaHei",sans-serif;background:#f6f7f9;
color:#111827;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
div{background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:32px 40px;text-align:center}
p{color:#6b7280;font-size:14px;margin:8px 0 0}</style></head>
<body><div><h2 id="title">正在完成登录…</h2>
<p id="hint">请稍候，完成后可关闭此页面。</p></div>
<script>
(function () {
  var params = new URLSearchParams(window.location.hash.slice(1));
  if (!params.toString()) params = new URLSearchParams(window.location.search);
  if (!params.get('access_token')) {
    document.getElementById('title').textContent = '登录未完成';
    document.getElementById('hint').textContent = '没有拿到授权信息，请回到启动器重试。';
    return;
  }
  fetch('/token?' + params.toString())
    .then(function () {
      document.getElementById('title').textContent = '登录成功';
      document.getElementById('hint').textContent = '可以关闭此页面并返回启动器。';
    })
    .catch(function () {
      document.getElementById('title').textContent = '回传失败';
      document.getElementById('hint').textContent = '请回到启动器重新登录。';
    });
})();
</script></body></html>
"""


class ChmlFrpError(Exception):
    """ChmlFrp 接口或节点返回的错误。"""


def normalize_expiry(value: object) -> float:
    """把过期时间统一成秒级时间戳（接口可能返回秒或毫秒）。"""
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        return 0.0
    if number > 10**12:
        number /= 1000
    return number


# ------------------------------------------------------------------ HTTP
def _call(
    path: str,
    *,
    access: str = "",
    params: Optional[dict] = None,
    body: Optional[dict] = None,
    timeout: int = 20,
) -> dict:
    url = f"{API_BASE}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {"Authorization": f"Bearer {access}"} if access else {}
    method = "POST" if body is not None else "GET"
    try:
        status, payload = net.request_json(
            url, method=method, json_body=body, headers=headers, timeout=timeout
        )
    except (OSError, ValueError) as exc:
        raise ChmlFrpError("ChmlFrp 服务暂时不可用，请检查网络后重试") from exc
    if not isinstance(payload, dict):
        raise ChmlFrpError("ChmlFrp 返回数据异常")
    if status >= 400 or payload.get("state") != "success":
        message = str(payload.get("msg") or payload.get("message") or f"请求失败（{status}）")
        raise ChmlFrpError(message)
    return payload


# ------------------------------------------------------------------ SSO 登录
class SsoListener:
    """本地回调服务：浏览器授权后把 hash 里的令牌回传给启动器。"""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._params: dict[str, str] = {}
        self._server: Optional[ThreadingHTTPServer] = None
        handler = self._handler()
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True, name="aml-chmlfrp-sso"
        )
        self._thread.start()

    def _handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 约定
                parsed = urllib.parse.urlsplit(self.path)
                if parsed.path == "/token":
                    outer._params = dict(urllib.parse.parse_qsl(parsed.query))
                    outer._event.set()
                    self._reply("ok", "text/plain; charset=utf-8")
                elif parsed.path in ("/", "/index.html"):
                    self._reply(LOGIN_HTML, "text/html; charset=utf-8")
                else:
                    self._reply("not found", "text/plain; charset=utf-8", status=404)

            def _reply(self, text: str, content_type: str, status: int = 200) -> None:
                data = text.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args) -> None:  # noqa: D401 - 静默日志
                return

        return Handler

    @property
    def return_url(self) -> str:
        assert self._server is not None
        port = int(self._server.server_address[1])
        return f"http://127.0.0.1:{port}/"

    def wait(self, timeout: float = 180.0) -> dict:
        if not self._event.wait(timeout):
            raise ChmlFrpError("登录超时，请重新点击登录")
        return dict(self._params)

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


def sso_login(*, timeout: float = 180.0, open_browser: bool = True) -> dict:
    """打开浏览器完成 ChmlFrp 授权，返回可保存的账户信息。"""
    listener = SsoListener()
    try:
        return_url = urllib.parse.quote(listener.return_url, safe="")
        url = f"{API_BASE}/sso/authorize?return_url={return_url}"
        if open_browser:
            webbrowser.open(url)
        params = listener.wait(timeout)
    finally:
        listener.close()
    access = str(params.get("access_token") or "").strip()
    if not access:
        raise ChmlFrpError("登录未完成或授权被取消")
    user = userinfo(access)
    usertoken = str(user.get("usertoken") or "").strip()
    if not usertoken:
        raise ChmlFrpError("登录成功，但没有获取到用户令牌")
    return {
        "username": str(user.get("username") or ""),
        "usertoken": usertoken,
        "access_token": access,
        "refresh_token": str(params.get("refresh_token") or ""),
        "expires_at": normalize_expiry(params.get("expires_at")),
    }


def refresh_session(refresh_token: str, *, timeout: int = 20) -> dict:
    """用 refresh_token 换新的 access_token。"""
    if not refresh_token:
        raise ChmlFrpError("登录已过期，请重新登录")
    payload = _call(
        "/sso/refresh", body={"refresh_token": refresh_token}, timeout=timeout
    )
    data = payload.get("data") or {}
    access = str(data.get("access_token") or "").strip()
    if not access:
        raise ChmlFrpError("登录已过期，请重新登录")
    return {
        "access_token": access,
        "refresh_token": str(data.get("refresh_token") or refresh_token),
        "expires_at": normalize_expiry(data.get("expires_at")),
    }


def logout(refresh_token: str) -> None:
    """退出 SSO；失败不影响本地清理。"""
    if not refresh_token:
        return
    try:
        _call("/sso/logout", body={"refresh_token": refresh_token}, timeout=10)
    except ChmlFrpError:
        pass


def userinfo(access: str, *, timeout: int = 20) -> dict:
    payload = _call("/userinfo", access=access, timeout=timeout)
    return payload.get("data") or {}


# ------------------------------------------------------------------ 节点
def list_nodes(*, timeout: int = 15) -> list[dict]:
    payload = _call("/node", timeout=timeout)
    data = payload.get("data")
    return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []


def node_detail(access: str, node: str, *, timeout: int = 15) -> dict:
    payload = _call(
        "/nodeinfo", access=access, params={"node": node}, timeout=timeout
    )
    return payload.get("data") or {}


def tcp_latency(host: str, port: int, *, timeout: float = 1.5) -> Optional[int]:
    """用 TCP 握手估算节点延迟（毫秒）；连不上返回 None。"""
    started = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            pass
    except (OSError, ValueError):
        return None
    return max(1, int((time.monotonic() - started) * 1000))


def available_nodes(
    access: str, *, timeout: float = 1.5, workers: int = 8
) -> list[dict]:
    """返回在线且可连通的节点，按延迟从低到高排序。"""
    from concurrent.futures import ThreadPoolExecutor

    nodes = list_nodes()
    if not nodes:
        return []

    def probe(item: dict) -> Optional[dict]:
        name = str(item.get("name") or "").strip()
        if not name:
            return None
        try:
            detail = node_detail(access, name, timeout=8)
        except ChmlFrpError:
            # VIP 节点对普通用户不可见，按不可用处理。
            return None
        if str(detail.get("state") or "").lower() != "online":
            return None
        host = str(detail.get("ip") or detail.get("realIp") or "").strip()
        port = int(detail.get("port") or DEFAULT_SERVER_PORT)
        if not host:
            return None
        latency = tcp_latency(host, port, timeout=timeout)
        if latency is None:
            return None
        return {
            "name": name,
            "area": str(item.get("area") or detail.get("area") or ""),
            "host": host,
            "port": port,
            "latency_ms": latency,
            "rport": detail.get("rport") or "",
            "udp": bool(detail.get("udp")),
        }

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(nodes)))) as pool:
        results = [item for item in pool.map(probe, nodes) if item]
    results.sort(key=lambda item: item["latency_ms"])
    return results


# ------------------------------------------------------------------ 隧道
def list_tunnels(access: str, *, timeout: int = 15) -> list[dict]:
    payload = _call("/tunnel", access=access, timeout=timeout)
    data = payload.get("data")
    return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []


def port_range(text: object) -> tuple[int, int]:
    """解析节点外网端口范围，例如 ``10000-65535``。"""
    numbers = [int(item) for item in re.findall(r"\d+", str(text or ""))]
    if len(numbers) >= 2:
        low, high = sorted(numbers[:2])
        low, high = max(1024, low), min(65535, high)
        if low <= high:
            return low, high
    if len(numbers) == 1 and 1024 <= numbers[0] <= 65535:
        return numbers[0], numbers[0]
    return DEFAULT_PORT_RANGE


def pick_remote_port(detail: dict, requested: int = 0) -> int:
    """用户指定了就用指定端口，否则在节点允许范围内随机。"""
    if int(requested or 0) > 0:
        port = int(requested)
        if not (1024 <= port <= 65535):
            raise ChmlFrpError("外网端口需在 1024-65535 之间")
        return port
    low, high = port_range(detail.get("rport"))
    if low == high:
        return low
    return random.SystemRandom().randint(low, high)


def tunnel_name_for(local_port: int) -> str:
    """固定前缀 + 内网端口：同一端口重复开房时复用/更新同一条隧道。"""
    return f"AML-MC-{int(local_port)}"


def normalize_tunnel_name(name: str, local_port: int) -> str:
    # 保留中英文、数字与下划线/短横线，其余字符替换成短横线。
    text = re.sub(r"[^\w-]", "-", str(name or "").strip(), flags=re.UNICODE)
    text = re.sub(r"-{2,}", "-", text).strip("-_")
    return text[:32] or tunnel_name_for(local_port)


def create_or_update_tunnel(
    access: str,
    usertoken: str,
    *,
    name: str,
    node: str,
    local_port: int,
    remote_port: int,
    encryption: bool = True,
    compression: bool = False,
    local_ip: str = DEFAULT_LOCAL_IP,
) -> dict:
    """同名隧道已存在时更新，否则新建，避免占用用户的隧道配额。"""
    existing = None
    try:
        existing = next(
            (item for item in list_tunnels(access) if str(item.get("name")) == name),
            None,
        )
    except ChmlFrpError:
        existing = None

    if existing and (existing.get("id") or existing.get("tunnelid")):
        _call(
            "/update_tunnel",
            access=access,
            body={
                "tunnelid": existing.get("id") or existing.get("tunnelid"),
                "tunnelname": name,
                "node": node,
                "porttype": "tcp",
                "localip": local_ip,
                "localport": int(local_port),
                "remoteport": int(remote_port),
                "encryption": "true" if encryption else "false",
                "compression": "true" if compression else "false",
                "extraparams": "",
            },
        )
        return {
            **existing,
            "name": name,
            "node": node,
            "nport": int(local_port),
            "dorp": str(remote_port),
            "type": "tcp",
        }

    payload = _call(
        "/create_tunnel",
        access=access,
        body={
            "token": usertoken,
            "tunnelname": name,
            "node": node,
            "porttype": "tcp",
            "localip": local_ip,
            "localport": int(local_port),
            "remoteport": int(remote_port),
            "encryption": bool(encryption),
            "compression": bool(compression),
            "extraparams": "",
        },
    )
    data = payload.get("data") or {}
    return {
        **data,
        "name": name,
        "node": node,
        "nport": int(local_port),
        "dorp": str(data.get("dorp") or remote_port),
    }


def tunnel_config(access: str, node: str, name: str, *, timeout: int = 20) -> str:
    """获取 frpc 配置（TOML 文本）。"""
    payload = _call(
        "/tunnel_config",
        access=access,
        params={
            "node": node,
            "tunnel_names": name,
            "protocol": "tcp",
            "format": "toml",
        },
        timeout=timeout,
    )
    text = str(payload.get("data") or "").strip()
    if not text:
        raise ChmlFrpError("ChmlFrp 没有返回隧道配置")
    return text + "\n"


def delete_tunnel(access: str, tunnel_id: str) -> bool:
    """删除隧道；失败时返回 False（隧道可在下次创建时复用）。"""
    if not tunnel_id:
        return False
    try:
        _call("/delete_tunnel", access=access, params={"tunnelid": tunnel_id})
        return True
    except ChmlFrpError:
        return False


def connect_address(detail: dict, tunnel: dict) -> str:
    """TCP 隧道的连接地址：节点域名 + 外网端口。"""
    host = str(detail.get("ip") or detail.get("realIp") or "").strip()
    dorp = str(tunnel.get("dorp") or "").strip()
    if not dorp:
        return host
    if ":" in dorp or not dorp.isdigit():
        return dorp
    return f"{host}:{dorp}" if host else dorp
