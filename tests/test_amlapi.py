"""AMLAPI 镜像（PoW 人机验证）的离线单元测试。

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import hashlib
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine import amlapi
from engine.mirror import AMLAPI_ROOT, MirrorManager


def _digest_ok(prefix: bytes, nonce: int, bits: int) -> bool:
    digest = hashlib.sha256(prefix + str(nonce).encode()).digest()
    return int.from_bytes(digest, "big") < 1 << (256 - bits)


class SolveTest(unittest.TestCase):
    """nonce 计算：结果必须真的满足前导零位数要求。"""

    def test_zero_difficulty_needs_no_work(self) -> None:
        self.assertEqual(amlapi.solve("chal", 0, threading.Event()), 0)

    def test_invalid_difficulty_treated_as_zero(self) -> None:
        self.assertEqual(amlapi.solve("chal", "abc", threading.Event()), 0)

    def test_inline_result_matches_threshold(self) -> None:
        # 不让测试真的拉起进程池，强制走单线程实现。
        with mock.patch.object(amlapi.multiprocessing, "get_context", side_effect=RuntimeError):
            nonce = amlapi.solve("chal", 8, threading.Event())
        self.assertIsNotNone(nonce)
        self.assertTrue(_digest_ok(b"chal:", int(nonce), 8))

    def test_single_cpu_uses_inline(self) -> None:
        with mock.patch.object(amlapi.multiprocessing, "cpu_count", return_value=1):
            nonce = amlapi.solve("chal", 8, threading.Event())
        self.assertIsNotNone(nonce)
        self.assertTrue(_digest_ok(b"chal:", int(nonce), 8))

    def test_cancel_returns_none(self) -> None:
        stop = threading.Event()
        stop.set()
        with mock.patch.object(amlapi.multiprocessing, "get_context", side_effect=RuntimeError):
            self.assertIsNone(amlapi.solve("chal", 8, stop))

    def test_worker_finds_valid_nonce(self) -> None:
        nonce = amlapi._solve_worker((b"x:", 1 << 252, 0, 1))
        self.assertTrue(_digest_ok(b"x:", nonce, 4))

    def test_request_swallows_network_error(self) -> None:
        with mock.patch.object(amlapi.net, "request_json", side_effect=OSError("boom")):
            self.assertEqual(amlapi._request("/pow/status"), (0, {}))


class PowVerifierTest(unittest.TestCase):
    """验证状态机：状态同步、回调只触发一次、失败分支。"""

    def _verifier(self) -> amlapi.PowVerifier:
        verifier = amlapi.PowVerifier()
        self.calls = 0
        verifier.on_verified.append(self._bump)
        return verifier

    def _bump(self) -> None:
        self.calls += 1

    def test_initial_status(self) -> None:
        verifier = self._verifier()
        status = verifier.status()
        self.assertEqual(status["state"], amlapi.STATE_IDLE)
        self.assertFalse(status["verified"])
        self.assertEqual(status["expires_in"], 0)

    def test_read_status_marks_verified_once(self) -> None:
        verifier = self._verifier()
        payload = {
            "verified": True,
            "expires_in": 600,
            "today_bytes": 123,
            "limit_bytes_per_second": 20 * 1024 * 1024,
            "active_connections": 2,
        }
        with mock.patch.object(amlapi, "_request", return_value=(200, payload)):
            self.assertTrue(verifier._read_status())
            self.assertTrue(verifier._read_status())

        self.assertTrue(verifier.verified)
        self.assertGreater(verifier.expires_in, 500)
        self.assertEqual(verifier.today_bytes, 123)
        self.assertEqual(verifier.limit_bps, 20 * 1024 * 1024)
        self.assertEqual(self.calls, 1)
        self.assertTrue(verifier.status()["verified"])

    def test_status_expiry_drops_verification(self) -> None:
        verifier = self._verifier()
        with mock.patch.object(amlapi, "_request", return_value=(200, {"verified": True, "expires_in": 600})):
            verifier._read_status()
        self.assertTrue(verifier.verified)
        with mock.patch.object(amlapi, "_request", return_value=(200, {"verified": False})):
            self.assertFalse(verifier._read_status())
        self.assertFalse(verifier.verified)
        self.assertEqual(verifier.status()["state"], amlapi.STATE_SOLVING)

    def test_mark_verified_fires_callback_only_once(self) -> None:
        verifier = self._verifier()
        verifier._mark_verified(600)
        verifier._mark_verified(600)
        self.assertEqual(self.calls, 1)

    def test_step_solves_challenge(self) -> None:
        verifier = self._verifier()

        def fake_request(path, payload=None, *, timeout=15):
            if path == "/pow/status":
                return 200, {"verified": False}
            if path == "/pow/start":
                return 200, {"challenge": "abc", "session_id": "s1", "difficulty": 4}
            if path == "/pow/submit":
                self.assertEqual(payload["session_id"], "s1")
                self.assertEqual(payload["nonce"], 12345)
                return 200, {"ok": True}
            raise AssertionError(f"未预期的请求：{path}")

        with mock.patch.object(amlapi, "_request", side_effect=fake_request), mock.patch.object(
            amlapi, "solve", return_value=12345
        ):
            wait = verifier._step()

        self.assertTrue(verifier.verified)
        self.assertEqual(verifier.state, amlapi.STATE_VERIFIED)
        self.assertEqual(self.calls, 1)
        self.assertEqual(wait, amlapi.VERIFY_WINDOW - amlapi.RENEW_MARGIN)

    def test_step_without_challenge_fails(self) -> None:
        verifier = self._verifier()
        with mock.patch.object(amlapi, "_request", return_value=(0, {})):
            wait = verifier._step()
        self.assertEqual(verifier.state, amlapi.STATE_FAILED)
        self.assertEqual(verifier.detail, "验证服务不可用")
        self.assertEqual(wait, 60)
        self.assertEqual(self.calls, 0)

    def test_step_solve_timeout_fails(self) -> None:
        verifier = self._verifier()

        def fake_request(path, payload=None, *, timeout=15):
            if path == "/pow/status":
                return 200, {"verified": False}
            return 200, {"challenge": "abc", "session_id": "s1", "difficulty": 30}

        with mock.patch.object(amlapi, "_request", side_effect=fake_request), mock.patch.object(
            amlapi, "solve", return_value=None
        ):
            wait = verifier._step()
        self.assertEqual(verifier.state, amlapi.STATE_FAILED)
        self.assertEqual(verifier.detail, "验证计算超时")
        self.assertEqual(wait, 30)

    def test_step_rejected_submit_fails(self) -> None:
        verifier = self._verifier()

        def fake_request(path, payload=None, *, timeout=15):
            if path == "/pow/status":
                return 200, {"verified": False}
            if path == "/pow/start":
                return 200, {"challenge": "abc", "session_id": "s1", "difficulty": 4}
            return 200, {"ok": False}

        with mock.patch.object(amlapi, "_request", side_effect=fake_request), mock.patch.object(
            amlapi, "solve", return_value=1
        ):
            wait = verifier._step()
        self.assertEqual(verifier.state, amlapi.STATE_FAILED)
        self.assertEqual(verifier.detail, "验证未通过")
        self.assertEqual(wait, 60)
        self.assertEqual(self.calls, 0)

    def test_stop_resets_state(self) -> None:
        verifier = self._verifier()
        verifier._mark_verified(600)
        verifier.stop()
        self.assertFalse(verifier.verified)
        self.assertEqual(verifier.state, amlapi.STATE_IDLE)
        self.assertEqual(verifier.detail, "已关闭")


class AmlapiCandidatesTest(unittest.TestCase):
    """AMLAPI 只镜像原版资源，且排在候选列表最前。"""

    ASSET_URL = "https://resources.download.minecraft.net/ab/abcdef0123"

    def _manager(self) -> MirrorManager:
        manager = MirrorManager()
        manager.set_amlapi(True)
        manager.amlapi_available = True
        return manager

    def test_assets_use_amlapi_first(self) -> None:
        candidates = self._manager().candidates(self.ASSET_URL)
        self.assertEqual(candidates[0], f"{AMLAPI_ROOT}/assets/ab/abcdef0123")
        self.assertEqual(candidates[-1], self.ASSET_URL)

    def test_metadata_skips_amlapi(self) -> None:
        url = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json"
        for candidate in self._manager().candidates(url):
            self.assertFalse(candidate.startswith(AMLAPI_ROOT))

    def test_disabled_amlapi_untouched(self) -> None:
        manager = MirrorManager()
        manager.amlapi_available = True
        self.assertNotIn(
            f"{AMLAPI_ROOT}/assets/ab/abcdef0123", manager.candidates(self.ASSET_URL)
        )

    def test_unreachable_amlapi_skipped(self) -> None:
        manager = self._manager()
        manager.amlapi_available = False
        self.assertNotIn(
            f"{AMLAPI_ROOT}/assets/ab/abcdef0123", manager.candidates(self.ASSET_URL)
        )

    def test_verified_bumps_epoch_only_for_amlapi(self) -> None:
        manager = self._manager()
        before = manager.amlapi_epoch
        manager._on_amlapi_verified()
        self.assertEqual(manager.amlapi_epoch, before + 1)
        # 代次只跟已重写后的 AMLAPI 地址挂钩，官方地址恒为 0。
        self.assertEqual(
            manager.source_epoch(f"{AMLAPI_ROOT}/assets/ab/abcdef0123"), before + 1
        )
        self.assertEqual(manager.source_epoch(self.ASSET_URL), 0)


if __name__ == "__main__":
    unittest.main()
