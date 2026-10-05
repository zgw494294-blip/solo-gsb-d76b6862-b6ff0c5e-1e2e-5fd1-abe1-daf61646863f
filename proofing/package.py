"""ZIP 校验与包构建。

校验规则（任一不满足即整体拒绝，不留下可预览的半包）：
  - 条目数（文件）不超过 100，解压总量不超过 10 MiB；
  - 仅允许 .html/.htm/.css/.png/.jpg/.jpeg，目录条目不限；
  - 拒绝绝对路径、含反斜杠、经规范化后逃逸包根（..）的条目；
  - 拒绝符号链接及其他非常规文件类型；
  - 拒绝规范化后重名的条目；
  - HTML/CSS 必须是合法 UTF-8；PNG/JPEG 校验魔数。
校验通过后一次性完成 HTML/CSS 重写并收集引用报告，全部成功才入库存储。
"""

from __future__ import annotations

import io
import posixpath
import re
import stat
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from urllib.parse import quote

from .refs import Report
from .rewriter_css import rewrite_css
from .rewriter_html import is_html, rewrite_html

MAX_FILES = 100
MAX_TOTAL_BYTES = 10 * 1024 * 1024  # 10 MiB（解压后总量）

ALLOWED_EXTS = {".html", ".htm", ".css", ".png", ".jpg", ".jpeg"}
IMAGE_EXTS = {".png", ".jpg", ".jpeg"}

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_SOI = b"\xff\xd8"
_JPEG_EOI = b"\xff\xd9"

_DRIVE_RE = re.compile(r"^[a-zA-Z]:")


class PackageError(Exception):
    """包校验/构建失败，消息可直接展示给用户。"""


@dataclass
class Package:
    id: str
    name: str
    created: float
    files: dict[str, bytes]  # 全部条目（图片为字节，HTML/CSS 为 UTF-8 字节）
    html_entries: list[str]
    rendered_html: dict[str, str] = field(default_factory=dict)
    rendered_css: dict[str, str] = field(default_factory=dict)
    report: Report = field(default_factory=Report)

    @property
    def total_size(self) -> int:
        return sum(len(b) for b in self.files.values())


def _check_entry_name(raw_name: str, seen: set[str]) -> str | None:
    """校验并规范化条目名；目录返回 None。非法时抛 PackageError。"""
    name = raw_name
    if not name or name != name.strip():
        raise PackageError(f"条目名非法（为空或首尾含空白）：{raw_name!r}")
    if name.startswith("/") or name.startswith("\\"):
        raise PackageError(f"条目含绝对路径，已拒绝：{raw_name!r}")
    if _DRIVE_RE.match(name):
        raise PackageError(f"条目含盘符绝对路径，已拒绝：{raw_name!r}")
    if "\\" in name:
        raise PackageError(f"条目含反斜杠，已拒绝：{raw_name!r}")
    if "\x00" in name:
        raise PackageError(f"条目含 NUL 字符，已拒绝：{raw_name!r}")

    is_dir = name.endswith("/")
    norm = posixpath.normpath(name)
    if norm == "." or norm == ".." or norm.startswith("../") or posixpath.isabs(norm):
        raise PackageError(f"条目经规范化后逃逸包根，已拒绝：{raw_name!r}")
    if norm in seen:
        raise PackageError(f"条目规范化后重名，已拒绝：{raw_name!r} 与 {norm!r}")
    seen.add(norm)
    return None if is_dir else norm


def _check_entry_type(info: zipfile.ZipInfo) -> None:
    mode = (info.external_attr >> 16) & 0xFFFF
    if mode == 0:
        return  # 未携带 Unix 权限位（常见于 Windows 打包），按常规文件处理
    kind = stat.S_IFMT(mode)
    if kind == 0:
        return  # 未标注类型位（仅有权限位），按常规文件处理
    if kind == stat.S_IFLNK:
        raise PackageError(f"条目为符号链接，已拒绝：{info.filename!r}")
    if kind not in (stat.S_IFREG, stat.S_IFDIR):
        raise PackageError(f"条目为非常规文件类型，已拒绝：{info.filename!r}")


def _read_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    with zf.open(info) as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise PackageError(f"条目 {info.filename!r} 解压后超出大小限制")
    return data


def load_package(filename: str, blob: bytes) -> Package:
    """从 ZIP 字节构建 Package；任何一步失败都抛 PackageError，不留半成品。"""
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile as exc:
        raise PackageError(f"不是有效的 ZIP 文件：{exc}") from exc

    with zf:
        infos = zf.infolist()
        if not infos:
            raise PackageError("ZIP 为空")

        seen: set[str] = set()
        members: list[tuple[str, zipfile.ZipInfo]] = []
        total = 0

        for info in infos:
            if info.flag_bits & 0x1:
                raise PackageError(f"条目被加密，已拒绝：{info.filename!r}")
            _check_entry_type(info)
            path = _check_entry_name(info.filename, seen)
            if path is None:
                continue  # 目录条目

            ext = posixpath.splitext(path)[1].lower()
            if ext not in ALLOWED_EXTS:
                raise PackageError(f"不支持的文件类型 {ext or '(无扩展名)'}，已拒绝：{path}")

            members.append((path, info))
            if len(members) > MAX_FILES:
                raise PackageError(f"文件数超过上限 {MAX_FILES} 个")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise PackageError("解压总量超过 10 MiB 上限")

        files: dict[str, bytes] = {}
        for path, info in members:
            data = _read_member(zf, info, MAX_TOTAL_BYTES)
            ext = posixpath.splitext(path)[1].lower()
            if ext in (".html", ".htm", ".css"):
                try:
                    text = data.decode("utf-8-sig")  # 容忍 BOM，其余必须严格 UTF-8
                except UnicodeDecodeError:
                    raise PackageError(f"文件不是合法 UTF-8，已拒绝：{path}")
                data = text.encode("utf-8")
            elif ext == ".png":
                if not data.startswith(_PNG_MAGIC):
                    raise PackageError(f"PNG 魔数校验失败，已拒绝：{path}")
            elif ext in (".jpg", ".jpeg"):
                if not (data.startswith(_JPEG_SOI) and data.endswith(_JPEG_EOI)):
                    raise PackageError(f"JPEG 魔数校验失败，已拒绝：{path}")
            files[path] = data

    html_entries = sorted(p for p in files if is_html(p))

    pkg = Package(
        id=uuid.uuid4().hex,
        name=filename or "未命名",
        created=time.time(),
        files=files,
        html_entries=html_entries,
    )

    def url_for_view(p: str) -> str:
        return f"/pkg/{pkg.id}/view/{quote(p, safe='/')}"

    def url_for_res(p: str) -> str:
        return f"/pkg/{pkg.id}/res/{quote(p, safe='/')}"

    def has_file(p: str) -> bool:
        return p in files

    # 一次性完成全部重写；任何异常都意味着构建失败，包不会入库
    for path in html_entries:
        text = files[path].decode("utf-8")
        pkg.rendered_html[path] = rewrite_html(text, path, has_file, url_for_view, url_for_res, pkg.report)
    for path in sorted(p for p in files if p.lower().endswith(".css")):
        text = files[path].decode("utf-8")
        pkg.rendered_css[path] = rewrite_css(text, path, has_file, url_for_res, pkg.report)

    return pkg
