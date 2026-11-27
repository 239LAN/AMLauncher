"""下载源镜像：默认镜像优先，镜像不可用时自动回退官方源。

设计要点：
- 只做「URL 重写 + 候选列表」，不改变上层调用方式；
- ``download_file`` / ``get_json`` / ``fetch_bytes`` 会依次尝试候选地址，
  因此单个文件可以先走镜像、失败再走官方，无需上层感知；
- 大文件分片下载时，下载器会轮换每个分片的候选顺序：相邻分片分别优先走
  不同镜像 / 官方源，多个源都可用时同时下载；任一源失败时该分片再回退另一个源；
- AMLAPI 是独立开关，只镜像原版游戏文件，可与 BMCLAPI、官方源同时使用；
  元数据（清单 / 版本 JSON）不走 AMLAPI，避免其改写后的地址让其它镜像失效；
- 不参与重写的是 OAuth / API 类请求（Modrinth、微软登录等），
  这些接口本就没有镜像，走 ``request_json`` 不经过候选逻辑。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import net
from .amlapi import AMLAPI_ROOT, PowVerifier

BMCLAPI_ROOT = "https://bmclapi2.bangbang93.com"

# 公共 GitHub 代理：Adoptium 的 JRE 等资源托管在 GitHub Release 上，直连经常卡住。
GH_PROXY = "https://v6.gh-proxy.org/"
GITHUB_RELEASE_PREFIXES = (
    "https://github.com/",
    "https://objects.githubusercontent.com/",
    "https://release-assets.githubusercontent.com/",
)

# 前缀重写规则：命中后拼到镜像根上。顺序敏感，长的前缀必须排在短的前面。
BMCLAPI_RULES: list[tuple[str, str]] = [
    ("https://launchermeta.mojang.com", BMCLAPI_ROOT),
    ("https://piston-meta.mojang.com", BMCLAPI_ROOT),
    ("https://piston-data.mojang.com", BMCLAPI_ROOT),
    ("https://launcher.mojang.com", BMCLAPI_ROOT),
    ("https://libraries.minecraft.net", f"{BMCLAPI_ROOT}/maven"),
    ("https://maven.minecraftforge.net", f"{BMCLAPI_ROOT}/maven"),
    ("https://files.minecraftforge.net/maven", f"{BMCLAPI_ROOT}/maven"),
    ("https://maven.neoforged.net/releases", f"{BMCLAPI_ROOT}/maven"),
    ("https://maven.neoforged.net", f"{BMCLAPI_ROOT}/maven"),
    ("https://maven.fabricmc.net", f"{BMCLAPI_ROOT}/maven"),
    ("https://maven.quiltmc.org", f"{BMCLAPI_ROOT}/maven"),
    ("https://resources.download.minecraft.net", f"{BMCLAPI_ROOT}/assets"),
    ("https://meta.fabricmc.net", f"{BMCLAPI_ROOT}/fabric-meta"),
    ("https://meta.quiltmc.org", f"{BMCLAPI_ROOT}/quilt-meta"),
]
BMCLAPI_RULES.sort(key=lambda rule: len(rule[0]), reverse=True)

# AMLAPI 只提供原版游戏资源：清单 / 版本 JSON / 依赖库 / 资源文件。
AMLAPI_RULES: list[tuple[str, str]] = [
    ("https://launchermeta.mojang.com", AMLAPI_ROOT),
    ("https://piston-meta.mojang.com", AMLAPI_ROOT),
    ("https://piston-data.mojang.com", AMLAPI_ROOT),
    ("https://launcher.mojang.com", AMLAPI_ROOT),
    ("https://libraries.minecraft.net", f"{AMLAPI_ROOT}/libraries"),
    ("https://resources.download.minecraft.net", f"{AMLAPI_ROOT}/assets"),
]
AMLAPI_RULES.sort(key=lambda rule: len(rule[0]), reverse=True)

# 探针：一个体积小、必定存在的镜像地址。
PROBE_URL = f"{BMCLAPI_ROOT}/mc/game/version_manifest_v2.json"
AMLAPI_PROBE_URL = f"{AMLAPI_ROOT}/mc/game/version_manifest_v2.json"
# 官方源探针：用于判断能否让镜像与官方源同时下载（官方不可达时只用镜像）。
OFFICIAL_PROBE_URL = "https://launchermeta.mojang.com/mc/game/version_manifest_v2.json"

SOURCE_OFFICIAL = "official"
SOURCE_BMCLAPI = "bmclapi"
SOURCE_AMLAPI = "amlapi"
SOURCE_AUTO = "auto"


@dataclass
class MirrorStatus:
    source: str
    active: str
    available: bool
    latency_ms: int
    checked_at: float = field(default_factory=time.time)
    amlapi_enabled: bool = False
    amlapi_available: Optional[bool] = None
    amlapi_latency_ms: int = 0
    amlapi: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        sources = [SOURCE_OFFICIAL]
        if self.active == SOURCE_BMCLAPI:
            sources.insert(0, SOURCE_BMCLAPI)
        if self.amlapi_enabled:
            sources.insert(0, SOURCE_AMLAPI)
        return {
            "source": self.source,
            "active": self.active,
            "available": self.available,
            "latency_ms": self.latency_ms,
            "checked_at": self.checked_at,
            "sources": sources,
            "amlapi_enabled": self.amlapi_enabled,
            "amlapi_available": self.amlapi_available,
            "amlapi_latency_ms": self.amlapi_latency_ms,
            "amlapi": self.amlapi,
        }


def rewrite(url: str) -> Optional[str]:
    """把官方地址重写成 BMCLAPI 地址；无法重写返回 None。"""
    for prefix, replacement in BMCLAPI_RULES:
        if url.startswith(prefix):
            return replacement + url[len(prefix) :]
    return None


def rewrite_amlapi(url: str) -> Optional[str]:
    """把官方地址重写成 AMLAPI 地址；无法重写返回 None。"""
    for prefix, replacement in AMLAPI_RULES:
        if url.startswith(prefix):
            return replacement + url[len(prefix) :]
    return None


def is_amlapi_url(url: str) -> bool:
    return url.startswith(AMLAPI_ROOT)


def is_metadata_url(url: str) -> bool:
    """清单 / 版本 JSON / 资源索引等元数据：交给官方或 BMCLAPI，不走 AMLAPI。

    AMLAPI 会把元数据里的下载地址改写成自己的地址，从而让 BMCLAPI 与官方源
    失去重写机会，因此元数据统一走未改写的来源。
    """
    path = url.split("?", 1)[0].lower()
    return path.endswith(".json") or "/v1/packages/" in path


class MirrorManager:
    """管理当前启用的下载源，并把自己安装进 net 层。"""

    def __init__(
        self,
        source: str = SOURCE_AUTO,
        *,
        amlapi: bool = False,
        probe_timeout: float = 4.0,
    ) -> None:
        self.source = source if source in {SOURCE_AUTO, SOURCE_OFFICIAL, SOURCE_BMCLAPI} else SOURCE_AUTO
        self.probe_timeout = probe_timeout
        self.mirror_enabled = self.source != SOURCE_OFFICIAL
        self.latency_ms = 0
        self.checked_at = 0.0
        # 官方源是否可达：可达时允许镜像与官方源同时下载不同分片。
        self.official_available = False
        self.official_latency_ms = 0
        self.official_checked_at = 0.0
        self._official_probe: Optional[threading.Thread] = None

        # AMLAPI：独立开关，只镜像原版资源，验证通过后不限速。
        self.amlapi_enabled = bool(amlapi)
        self.amlapi_available: Optional[bool] = None
        self.amlapi_latency_ms = 0
        self.amlapi_checked_at = 0.0
        self._amlapi_probe: Optional[threading.Thread] = None
        # 每次验证通过自增：下载器据此重开 AMLAPI 未完成的连接。
        self._amlapi_epoch = 0
        self.verifier = PowVerifier()
        self.verifier.on_verified.append(self._on_amlapi_verified)

    # ------------------------------------------------------------- 候选择序
    @property
    def active(self) -> str:
        if self.source == SOURCE_OFFICIAL or not self.mirror_enabled:
            return SOURCE_OFFICIAL
        return SOURCE_BMCLAPI

    @property
    def amlapi_epoch(self) -> int:
        return self._amlapi_epoch

    def candidates(self, url: str) -> list[str]:
        """返回该 URL 的候选地址列表：AMLAPI → BMCLAPI → 官方。"""
        result: list[str] = []
        if self.amlapi_enabled and self.amlapi_available is not False and not is_metadata_url(url):
            mirrored = rewrite_amlapi(url)
            if mirrored and mirrored != url:
                result.append(mirrored)
        if self.active == SOURCE_BMCLAPI:
            mirrored = rewrite(url)
            if mirrored and mirrored != url:
                result.append(mirrored)
        if url.startswith(GITHUB_RELEASE_PREFIXES):
            proxied = f"{GH_PROXY}{url}"
            if proxied not in result:
                result.insert(0, proxied)
        if url not in result:
            result.append(url)
        return result

    def dual_source(self) -> bool:
        """是否有两个及以上可用源（决定是否让多个源同时承担分片下载）。"""
        sources = 0
        if self.amlapi_enabled and self.amlapi_available is not False:
            sources += 1
        if self.active == SOURCE_BMCLAPI and self.mirror_enabled:
            sources += 1
        if self.official_available:
            sources += 1
        return sources > 1

    def install(self) -> None:
        net.set_url_candidates(self.candidates)
        net.set_dual_source_policy(self.dual_source)
        net.set_source_epoch(self.source_epoch)

    def source_epoch(self, url: str) -> int:
        """AMLAPI 地址的验证代次；其它地址恒为 0（不参与连接重建）。"""
        return self._amlapi_epoch if is_amlapi_url(url) else 0

    def set_source(self, source: str) -> None:
        self.source = source if source in {SOURCE_AUTO, SOURCE_OFFICIAL, SOURCE_BMCLAPI} else SOURCE_AUTO
        self.mirror_enabled = self.source != SOURCE_OFFICIAL

    def set_amlapi(self, enabled: bool) -> None:
        """开关 AMLAPI：开启后立即探测并启动后台验证。"""
        self.amlapi_enabled = bool(enabled)
        if not self.amlapi_enabled:
            self.verifier.stop()
            self.amlapi_available = None
            return
        self._probe_amlapi_in_background()
        self.verifier.start()

    def set_logger(self, fn: Callable[[str], None]) -> None:
        self.verifier.log = fn

    # ------------------------------------------------------------ 验证回调
    def _on_amlapi_verified(self) -> None:
        self._amlapi_epoch += 1

    # ------------------------------------------------------------------ 测速
    def probe(self) -> MirrorStatus:
        """探测下载源可用性；镜像失败时本次会话内退回官方源。"""
        if self.amlapi_enabled:
            self._probe_amlapi_in_background()
            self.verifier.refresh_status()
        if self.source == SOURCE_OFFICIAL:
            self.mirror_enabled = False
            self._probe_official_in_background()
            self.checked_at = time.time()
            return self.status()

        self._probe_official_in_background()
        start = time.monotonic()
        try:
            with net._open(PROBE_URL, timeout=self.probe_timeout) as response:  # noqa: SLF001
                response.read(256)
            self.latency_ms = int((time.monotonic() - start) * 1000)
            self.mirror_enabled = True
        except Exception:  # noqa: BLE001 - 任何失败都视为镜像不可用
            self.latency_ms = 0
            # 自动模式探测失败直接用官方源，避免每个文件都先等镜像超时。
            self.mirror_enabled = self.source == SOURCE_BMCLAPI
        self.checked_at = time.time()
        return self.status()

    def _probe_official_in_background(self) -> None:
        """官方源探测放到后台线程，避免拖慢镜像探测 / 启动。"""
        if self._official_probe is not None and self._official_probe.is_alive():
            return
        self._official_probe = threading.Thread(
            target=self._probe_official, daemon=True
        )
        self._official_probe.start()

    def _probe_official(self) -> None:
        start = time.monotonic()
        try:
            with net._open(  # noqa: SLF001
                OFFICIAL_PROBE_URL, timeout=min(self.probe_timeout, 5.0)
            ) as response:
                response.read(256)
            self.official_latency_ms = int((time.monotonic() - start) * 1000)
            self.official_available = True
        except Exception:  # noqa: BLE001 - 官方不可达时保持单镜像下载
            self.official_latency_ms = 0
            self.official_available = False
        self.official_checked_at = time.time()

    def _probe_amlapi_in_background(self) -> None:
        if not self.amlapi_enabled:
            return
        if self._amlapi_probe is not None and self._amlapi_probe.is_alive():
            return
        self._amlapi_probe = threading.Thread(target=self._probe_amlapi, daemon=True)
        self._amlapi_probe.start()

    def _probe_amlapi(self) -> None:
        start = time.monotonic()
        try:
            with net._open(  # noqa: SLF001
                AMLAPI_PROBE_URL, timeout=min(self.probe_timeout, 6.0)
            ) as response:
                response.read(256)
            self.amlapi_latency_ms = int((time.monotonic() - start) * 1000)
            self.amlapi_available = True
        except Exception:  # noqa: BLE001 - AMLAPI 不可达时只用其它源
            self.amlapi_latency_ms = 0
            self.amlapi_available = False
        self.amlapi_checked_at = time.time()
        if self.amlapi_available and self.amlapi_enabled:
            self.verifier.start()

    def status(self) -> MirrorStatus:
        return MirrorStatus(
            source=self.source,
            active=self.active,
            available=self.latency_ms > 0,
            latency_ms=self.latency_ms,
            checked_at=self.checked_at or time.time(),
            amlapi_enabled=self.amlapi_enabled,
            amlapi_available=self.amlapi_available,
            amlapi_latency_ms=self.amlapi_latency_ms,
            amlapi=self.verifier.status(),
        )


# 进程级默认实例，供 UI / 服务层共享。
manager = MirrorManager()


def install(source: str = SOURCE_AUTO, *, amlapi: Optional[bool] = None) -> MirrorStatus:
    """按给定来源安装镜像重写，并做一次探测。"""
    manager.set_source(source)
    if amlapi is not None:
        manager.set_amlapi(amlapi)
    manager.install()
    return manager.probe()
