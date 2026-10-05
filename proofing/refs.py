"""引用解析与问题引用报告。

所有 HTML / CSS 中出现的引用统一走 resolve_reference()：
  - 相对地址    -> 按所属文件所在目录解析
  - 根相对地址  -> 以包根为基准（"/x/y.png" 指包内 x/y.png）
  - 绝对 URL    -> 包外引用，记录且不发起请求
解析结果状态：
  fragment      纯锚点，原样保留
  internal      解析到包内路径（是否存在由调用方判断）
  missing       （由调用方在包内查不到时标记）
  out-of-bounds 经规范化后逃逸包根
  external      http/https/协议相对等包外地址
  unsupported   javascript:/data:/mailto: 等不支持或非法的形式
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from urllib.parse import unquote

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*):")

# 状态 -> 中文标签（报告展示用）
STATUS_LABELS = {
    "missing": "缺失",
    "out-of-bounds": "越界",
    "external": "包外引用",
    "unsupported": "不支持",
}


@dataclass
class Reference:
    """一条被拦截的问题引用。"""

    source: str  # 来源文件（包内路径）
    context: str  # 出现位置，如 img[src]、css url()
    target: str  # 原始目标（原文照录）
    status: str  # missing / out-of-bounds / external / unsupported
    detail: str = ""  # 补充说明（如解析后的包内路径）


@dataclass
class Report:
    """一个包的全部问题引用。"""

    entries: list[Reference] = field(default_factory=list)

    def add(self, source: str, context: str, target: str, status: str, detail: str = "") -> None:
        self.entries.append(
            Reference(
                source=source,
                context=context,
                target=target[:500],
                status=status,
                detail=detail[:500],
            )
        )

    def count(self, status: str) -> int:
        return sum(1 for e in self.entries if e.status == status)


def resolve_reference(base_dir: str, raw_target: str) -> tuple[str, str | None]:
    """把 raw_target 按 base_dir（所属文件目录，包内 posix 路径）解析。

    返回 (status, package_path_or_None)。status 为 internal 时第二个值是
    规范化后的包内路径；其余状态第二个值为 None。
    """
    target = (raw_target or "").strip()
    if not target or target.startswith("#"):
        return "fragment", None

    # 协议相对地址 //host/path 一律视为包外
    if target.startswith("//"):
        return "external", None

    m = _SCHEME_RE.match(target)
    if m:
        scheme = m.group(1).lower()
        if scheme in ("http", "https"):
            return "external", None
        # javascript: data: mailto: tel: blob: 等一律不支持
        return "unsupported", None

    # 去掉 query / fragment 再解析路径
    path = target.split("#", 1)[0].split("?", 1)[0]
    try:
        # 先解码百分号编码，使 %2e%2e%2f 之类的逃逸在规范化时现形
        path = unquote(path, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return "unsupported", None
    if not path:
        return "fragment", None
    # 反斜杠在 zip 规范里不是分隔符，但部分浏览器会当分隔符处理，直接拒绝
    if "\\" in path:
        return "unsupported", None

    if path.startswith("/"):
        candidate = path.lstrip("/")
    elif base_dir:
        candidate = posixpath.join(base_dir, path)
    else:
        candidate = path

    norm = posixpath.normpath(candidate)
    if norm == ".":
        norm = ""
    if norm == ".." or norm.startswith("../"):
        return "out-of-bounds", None
    return "internal", norm
