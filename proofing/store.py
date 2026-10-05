"""内存包存储：进程内保存已通过的包，重启即清空。"""

from __future__ import annotations

import threading
from collections import OrderedDict

from .package import Package

_MAX_PACKAGES = 20  # 超出后按最旧逐出，防止内存无限增长


class PackageStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pkgs: OrderedDict[str, Package] = OrderedDict()

    def add(self, pkg: Package) -> None:
        with self._lock:
            self._pkgs[pkg.id] = pkg
            while len(self._pkgs) > _MAX_PACKAGES:
                self._pkgs.popitem(last=False)

    def get(self, pkg_id: str) -> Package | None:
        with self._lock:
            return self._pkgs.get(pkg_id)

    def remove(self, pkg_id: str) -> bool:
        with self._lock:
            return self._pkgs.pop(pkg_id, None) is not None

    def list(self) -> list[Package]:
        with self._lock:
            return sorted(self._pkgs.values(), key=lambda p: p.created, reverse=True)
