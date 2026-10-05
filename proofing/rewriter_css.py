"""CSS 重写：解析 url()，移除 @import。

url() 按所属 CSS 文件所在目录解析；根相对地址指向包根。
命中的包内资源改写成 /pkg/<id>/res/<path>；缺失 / 越界 / 包外 / 不支持
的目标记入报告并替换为 none，保证不发起任何请求。
@import 不支持，整条规则移除并记录。
"""

from __future__ import annotations

import posixpath
import re
from typing import Callable

from .refs import Report, resolve_reference

# url(...) / url('...') / url("...")，允许跨行
_URL_RE = re.compile(r"url\(\s*(['\"]?)(.*?)\1\s*\)", re.IGNORECASE | re.DOTALL)
# @import "x.css"; / @import url(x.css) screen and (...);  整条移除
_IMPORT_RE = re.compile(r"@import\b[^;]{0,1000};", re.IGNORECASE)


def rewrite_css(
    css_text: str,
    css_path: str,
    has_file: Callable[[str], bool],
    url_for_res: Callable[[str], str],
    report: Report,
) -> str:
    """重写 css_text（css_path 为其包内路径），返回安全 CSS。"""
    base_dir = posixpath.dirname(css_path)

    def _strip_import(m: re.Match) -> str:
        report.add(css_path, "css @import", m.group(0).strip(), "unsupported", "不支持 @import，已移除")
        return ""

    css_text = _IMPORT_RE.sub(_strip_import, css_text)

    def _rewrite_url(m: re.Match) -> str:
        raw = m.group(2).strip()
        status, path = resolve_reference(base_dir, raw)
        if status == "internal":
            if has_file(path):
                return f'url("{url_for_res(path)}")'
            report.add(css_path, "css url()", raw, "missing", f"解析为包内路径 {path}，但包中不存在")
            return "none"
        if status == "fragment":
            return m.group(0)
        if status == "out-of-bounds":
            report.add(css_path, "css url()", raw, "out-of-bounds", "经 ../ 规范化后逃逸包根")
        elif status == "external":
            report.add(css_path, "css url()", raw, "external", "包外地址，不发起请求")
        else:  # unsupported
            report.add(css_path, "css url()", raw, "unsupported", "不支持的地址形式")
        return "none"

    return _URL_RE.sub(_rewrite_url, css_text)
