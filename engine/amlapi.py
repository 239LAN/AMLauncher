"""AMLAPI 镜像的人机验证（CXCAPTCHA PoW）。

AMLAPI 提供 Minecraft 原版游戏文件镜像，未验证时单地址限速 4 MiB/s，
验证通过后 20 分钟内不限速。验证不阻塞下载：下载先按普通请求开始，
这里在后台申请挑战、本地计算、提交校验；通过后通知下载器重开连接，
把 AMLAPI 未下载完的部分切到不限速通道。

难度 ``difficulty`` 表示 SHA-256 摘要前导零的**位数**（实测 27 位，
即摘要整数小于 2**(256-27)），计算用多进程并行。
"""

from __future__ import annotations

import hashlib
import multiprocessing
import threading
import time
from typing import Callable, Optional

from . import net

AMLAPI_ROOT = "https://cxmc.net/amlapi"

# 验证通过后的有效期（秒）与提前续期余量。
VERIFY_WINDOW = 1200
RENEW_MARGIN = 120
# 单个挑战的最长计算时间：超时后重新申请挑战。
SOLVE_TIMEOUT = 240
# 并行计算的进程数上限，避免启动器把整机 CPU 占满。
MAX_SOLVE_WORKERS = 8
# 难度上限（前导零位数），防止异常响应导致死循环。
MAX_DIFFICULTY = 40

STATE_IDLE = "idle"
STATE_SOLVING = "solving"
STATE_VERIFIED = "verified"
STATE_FAILED = "failed"


def _request(path: str, payload: Optional[dict] = None, *, timeout: int = 15) -> tuple[int, dict]:
    """调用 AMLAPI 接口；网络异常统一返回 (0, {})。"""
    try:
        return net.request_json(
            AMLAPI_ROOT + path,
            method="POST" if payload is not None else "GET",
            json_body=payload if payload is not None else None,
            timeout=timeout,
        )
    except Exception:  # noqa: BLE001 - 验证失败不应影响下载
        return 0, {}


def _solve_worker(args: tuple[bytes, int, int, int]) -> int:
    """在 [start, start+step, ...] 上搜索满足前导零位数的 nonce。"""
    prefix, threshold, start, step = args
    nonce = start
    while True:
        digest = hashlib.sha256(prefix + str(nonce).encode()).digest()
        if int.from_bytes(digest, "big") < threshold:
            return nonce
        nonce += step


def _solve_inline(prefix: bytes, threshold: int, stop: threading.Event) -> Optional[int]:
    nonce = 0
    while not stop.is_set():
        for _ in range(20000):
            digest = hashlib.sha256(prefix + str(nonce).encode()).digest()
            if int.from_bytes(digest, "big") < threshold:
                return nonce
            nonce += 1
    return None


def solve(challenge: str, difficulty: int, stop: threading.Event) -> Optional[int]:
    """计算满足难度的 nonce；被取消或超时返回 None。"""
    try:
        bits = int(difficulty or 0)
    except (TypeError, ValueError):
        bits = 0
    if bits <= 0:
        return 0
    bits = min(bits, MAX_DIFFICULTY)
    prefix = f"{challenge}:".encode()
    threshold = 1 << (256 - bits)
    workers = max(1, min(MAX_SOLVE_WORKERS, multiprocessing.cpu_count()))

    pool = None
    try:
        if workers > 1:
            ctx = multiprocessing.get_context("spawn")
            pool = ctx.Pool(workers)
            jobs = [
                pool.apply_async(_solve_worker, ((prefix, threshold, index, workers),))
                for index in range(workers)
            ]
            deadline = time.monotonic() + SOLVE_TIMEOUT
            while time.monotonic() < deadline:
                if stop.is_set():
                    return None
                for job in jobs:
                    if job.ready():
                        try:
                            return int(job.get())
                        except Exception:  # noqa: BLE001 - 单个进程异常时继续等待其它进程
                            continue
                time.sleep(0.15)
            return None
    except Exception:  # noqa: BLE001 - 无法创建进程池时退回单线程计算
        pass
    finally:
        if pool is not None:
            try:
                pool.terminate()
            except Exception:  # noqa: BLE001
                pass
    return _solve_inline(prefix, threshold, stop)


class PowVerifier:
    """后台维护 AMLAPI 的验证状态。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.state = STATE_IDLE
        self.detail = "未验证"
        self.verified = False
        self.expires_at = 0.0
        self.today_bytes = 0
        self.limit_bps: Optional[int] = None
        self.active_connections = 0
        # 验证由未通过转为通过时触发，用于让下载器重开 AMLAPI 连接。
        self.on_verified: list[Callable[[], None]] = []
        self.log: Optional[Callable[[str], None]] = None

    # ------------------------------------------------------------ 生命周期
    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="amlapi-pow", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.verified = False
        self.state = STATE_IDLE
        self.detail = "已关闭"

    def refresh_status(self) -> None:
        """同步一次验证状态（供「探测镜像」按钮使用）。"""
        self._read_status()

    # ---------------------------------------------------------------- 状态
    @property
    def expires_in(self) -> int:
        if not self.verified:
            return 0
        return max(0, int(self.expires_at - time.time()))

    def status(self) -> dict:
        return {
            "state": self.state,
            "detail": self.detail,
            "verified": bool(self.verified and self.expires_in > 0),
            "expires_in": self.expires_in,
            "today_bytes": self.today_bytes,
            "limit_bps": self.limit_bps,
            "active_connections": self.active_connections,
        }

    # ---------------------------------------------------------------- 内部
    def _emit(self, message: str) -> None:
        if self.log is not None:
            try:
                self.log(message)
            except Exception:  # noqa: BLE001 - 日志失败不影响验证
                pass

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                wait = self._step()
            except Exception as exc:  # noqa: BLE001 - 保持后台线程存活
                self.state = STATE_FAILED
                self.detail = f"验证失败：{exc}"
                wait = 30
            self._stop.wait(max(5, wait))

    def _step(self) -> int:
        """执行一轮状态检查 / 计算，返回下次检查前等待的秒数。"""
        if self._read_status() and self.expires_in > RENEW_MARGIN:
            if not self.verified:
                self._mark_verified(self.expires_in)
            return self.expires_in - RENEW_MARGIN

        self.state = STATE_SOLVING
        self.detail = "后台验证中"
        self._emit("AMLAPI 开始后台人机验证（PoW）")
        code, challenge = _request("/pow/start", {})
        if code != 200 or not challenge.get("challenge") or not challenge.get("session_id"):
            self.state = STATE_FAILED
            self.detail = "验证服务不可用"
            return 60

        nonce = solve(
            str(challenge["challenge"]), int(challenge.get("difficulty") or 0), self._stop
        )
        if nonce is None:
            self.state = STATE_FAILED
            self.detail = "验证计算超时"
            return 30

        code, result = _request(
            "/pow/submit",
            {"session_id": challenge["session_id"], "nonce": nonce},
            timeout=20,
        )
        if code == 200 and result.get("ok"):
            self._mark_verified(VERIFY_WINDOW)
            self._emit("AMLAPI 人机验证通过，20 分钟内下载不限速")
            return VERIFY_WINDOW - RENEW_MARGIN
        self.state = STATE_FAILED
        self.detail = "验证未通过"
        return 60

    def _read_status(self) -> bool:
        code, payload = _request("/pow/status", timeout=10)
        if code != 200:
            return False
        self.today_bytes = int(payload.get("today_bytes") or 0)
        limit = payload.get("limit_bytes_per_second")
        self.limit_bps = int(limit) if isinstance(limit, (int, float)) else None
        self.active_connections = int(payload.get("active_connections") or 0)
        if payload.get("verified"):
            expires = int(payload.get("expires_in") or 0)
            self.expires_at = time.time() + max(0, expires)
            if not self.verified:
                self._mark_verified(expires)
                self._emit("AMLAPI 已处于验证有效期，下载不限速")
        elif self.verified:
            # 有效期已过，回到限速状态。
            self.verified = False
            self.expires_at = 0.0
            self.state = STATE_SOLVING
            self.detail = "验证过期，重新验证中"
        return bool(payload.get("verified"))

    def _mark_verified(self, window: int) -> None:
        first_time = not self.verified
        self.verified = True
        self.expires_at = time.time() + max(1, int(window))
        self.state = STATE_VERIFIED
        self.detail = "已验证，不限速"
        if not first_time:
            return
        for callback in list(self.on_verified):
            try:
                callback()
            except Exception:  # noqa: BLE001 - 回调异常不影响验证状态
                pass
