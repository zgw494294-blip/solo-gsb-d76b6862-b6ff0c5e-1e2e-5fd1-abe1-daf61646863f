"""HTML 重写与净化。

基于标准库 html.parser 逐标签重建文档：
  - 样式表 <link>、图片 <img>/<source>、页面链接 <a>/<area>、srcset、
    内联 style 属性与 <style> 块中的 url() 全部按所属文件目录解析，
    根相对地址指向包根，命中包内文件则改写为 /pkg/<id>/... 的隔离地址；
  - 缺失 / 越界 / 包外 / 不支持的引用记入报告并移除，不发起请求；
  - <base> 直接丢弃，不改变解析基准；
  - 脚本、事件属性（on*）、表单、嵌套框架、object/embed、meta 刷新等
    一律禁用；保留内嵌样式（<style> 与 style 属性，url() 照常重写）。
"""

from __future__ import annotations

import posixpath
from html import escape
from html.parser import HTMLParser
from typing import Callable

from .refs import Report, resolve_reference
from .rewriter_css import rewrite_css

HTML_EXTS = (".html", ".htm")

# 连内容一起丢弃的标签（脚本 / 表单 / 嵌套框架 / 插件 / 音视频）
_DROP_WITH_CONTENT = {
    "script", "form", "iframe", "frame", "frameset",
    "object", "embed", "applet", "audio", "video", "template",
}
# 单独丢弃的标签
_DROP_SINGLE = {"base", "noframes"}

_VOID = {
    "area", "br", "col", "hr", "img", "input", "link", "meta",
    "param", "source", "track", "wbr",
}

# 一律剥掉的属性：事件、表单提交、弹窗目标、srcdoc 等
_ATTRS_DROP = {
    "srcdoc", "formaction", "ping", "target", "action", "form",
    "integrity", "nonce", "poster", "background", "data", "xlink:href",
}


def is_html(path: str) -> bool:
    return path.lower().endswith(HTML_EXTS)


class _Rewriter(HTMLParser):
    def __init__(
        self,
        html_path: str,
        has_file: Callable[[str], bool],
        url_for_view: Callable[[str], str],
        url_for_res: Callable[[str], str],
        report: Report,
    ) -> None:
        super().__init__(convert_charrefs=True)
        self.html_path = html_path
        self.base_dir = posixpath.dirname(html_path)
        self.has_file = has_file
        self.url_for_view = url_for_view
        self.url_for_res = url_for_res
        self.report = report
        self.out: list[str] = []
        self._skip: list[str] = []  # 正在丢弃的标签栈
        self._in_style = 0  # 位于保留的 <style> 内的深度

    # ---------- 引用解析 ----------

    def _resolve(self, raw: str, context: str) -> tuple[str | None, str | None]:
        """返回 (包内路径或None, 错误状态或None)。错误已计入报告。"""
        status, path = resolve_reference(self.base_dir, raw)
        if status == "internal":
            if self.has_file(path):
                return path, None
            self.report.add(self.html_path, context, raw, "missing", f"解析为包内路径 {path}，但包中不存在")
            return None, "missing"
        if status == "fragment":
            return None, None
        if status == "out-of-bounds":
            self.report.add(self.html_path, context, raw, "out-of-bounds", "经 ../ 规范化后逃逸包根")
        elif status == "external":
            self.report.add(self.html_path, context, raw, "external", "包外地址，不发起请求")
        elif status == "unsupported":
            self.report.add(self.html_path, context, raw, "unsupported", "不支持的地址形式")
        return None, status

    def _page_link(self, raw: str, context: str) -> str | None:
        """<a>/<area> 的 href：包内页面 -> view 地址，包内资源 -> res 地址。"""
        status, _ = resolve_reference(self.base_dir, raw)
        if status == "fragment":
            return raw.strip()  # 纯锚点原样保留
        path, err = self._resolve(raw, context)
        if path is None:
            return None
        if is_html(path):
            return self.url_for_view(path)
        return self.url_for_res(path)

    def _resource(self, raw: str, context: str) -> str | None:
        """<img> 等资源的 src：仅包内文件可用。"""
        path, _ = self._resolve(raw, context)
        if path is None:
            return None
        return self.url_for_res(path)

    def _srcset(self, raw: str, context: str) -> str | None:
        """重写 srcset 候选列表；全部不可用则返回 None。"""
        kept: list[str] = []
        for piece in raw.split(","):
            tokens = piece.split()
            if not tokens:
                continue
            url, descriptors = tokens[0], tokens[1:]
            new_url = self._resource(url, context)
            if new_url:
                kept.append(" ".join([new_url, *descriptors]))
        return ", ".join(kept) if kept else None

    def _inline_css(self, css_text: str) -> str:
        return rewrite_css(css_text, self.html_path, self.has_file, self.url_for_res, self.report)

    # ---------- 标签处理 ----------

    def _build_attrs(self, tag: str, attrs: list[tuple[str, str | None]]) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for name, value in attrs:
            n = name.lower()
            v = value if value is not None else ""
            if n.startswith("on") or n in _ATTRS_DROP:
                continue
            if n == "style":
                out.append(("style", self._inline_css(v)))
                continue
            if n == "href":
                if tag in ("a", "area"):
                    new_v = self._page_link(v, f"{tag}[href]")
                    if new_v:
                        out.append(("href", new_v))
                # 其余标签（use/image/svg 等）的 href 一律剥掉
                continue
            if n == "src":
                if tag == "img":
                    new_v = self._resource(v, "img[src]")
                    if new_v:
                        out.append(("src", new_v))
                # 其他标签的 src（script/iframe/audio...）随标签或在此剥掉
                continue
            if n == "srcset":
                if tag in ("img", "source"):
                    new_v = self._srcset(v, f"{tag}[srcset]")
                    if new_v:
                        out.append(("srcset", new_v))
                continue
            out.append((n, v))
        return out

    def _emit(self, tag: str, attrs: list[tuple[str, str]], selfclose: bool) -> None:
        attr_text = "".join(f' {n}="{escape(v, quote=True)}"' for n, v in attrs)
        if selfclose and tag not in _VOID:
            self.out.append(f"<{tag}{attr_text}></{tag}>")
        else:
            self.out.append(f"<{tag}{attr_text}>")

    def _start(self, tag: str, attrs: list[tuple[str, str | None]], selfclose: bool) -> None:
        if self._skip:
            if tag in _DROP_WITH_CONTENT and not selfclose:
                self._skip.append(tag)
            return
        if tag in _DROP_WITH_CONTENT:
            if not selfclose:
                self._skip.append(tag)
            return
        if tag in _DROP_SINGLE:
            return
        if tag == "meta":
            # http-equiv（刷新/跳转等）一律丢弃，保留 charset 等说明性 meta
            if any((n.lower() == "http-equiv") for n, _ in attrs):
                return
        if tag == "link":
            self._handle_link(attrs)
            return
        if tag == "style":
            if not selfclose:
                self._in_style += 1
            self._emit(tag, self._build_attrs(tag, attrs), selfclose)
            return
        if tag == "source":
            # 仅保留 picture 中 img 候选的 srcset 用法；src 已在属性层剥掉
            self._emit(tag, self._build_attrs(tag, attrs), True)
            return
        self._emit(tag, self._build_attrs(tag, attrs), selfclose)

    def _handle_link(self, attrs: list[tuple[str, str | None]]) -> None:
        rel = ""
        href: str | None = None
        for n, v in attrs:
            if n.lower() == "rel" and v:
                rel = v.lower()
            elif n.lower() == "href" and v is not None:
                href = v
        if "stylesheet" not in rel or href is None:
            return  # icon/preload/预取等非样式表 link 直接丢弃
        path, _ = self._resolve(href, "link[stylesheet]")
        if path is None:
            return
        self.out.append(f'<link rel="stylesheet" href="{escape(self.url_for_res(path), quote=True)}">')

    # ---------- HTMLParser 回调 ----------

    def handle_starttag(self, tag, attrs):
        self._start(tag, attrs, selfclose=False)

    def handle_startendtag(self, tag, attrs):
        self._start(tag, attrs, selfclose=True)

    def handle_endtag(self, tag):
        if self._skip:
            if tag == self._skip[-1]:
                self._skip.pop()
            return
        if tag in _DROP_WITH_CONTENT or tag in _DROP_SINGLE or tag in _VOID:
            return
        if tag == "style":
            if self._in_style:
                self._in_style -= 1
            self.out.append("</style>")
            return
        self.out.append(f"</{tag}>")

    def handle_data(self, data):
        if self._skip:
            return
        if self._in_style:
            self.out.append(self._inline_css(data))
        else:
            self.out.append(escape(data, quote=False))

    def handle_decl(self, decl):
        if decl.strip().lower().startswith("doctype"):
            self.out.append("<!DOCTYPE html>")

    def handle_comment(self, data):
        pass  # 注释一律丢弃（避免条件注释藏负载）

    def handle_entityref(self, name):
        if not self._skip:
            self.out.append(f"&{name};")

    def handle_charref(self, name):
        if not self._skip:
            self.out.append(f"&#{name};")

    def handle_pi(self, data):
        pass

    def unknown_decl(self, data):
        pass  # CDATA 等不输出


def rewrite_html(
    html_text: str,
    html_path: str,
    has_file: Callable[[str], bool],
    url_for_view: Callable[[str], str],
    url_for_res: Callable[[str], str],
    report: Report,
) -> str:
    """重写 html_text（html_path 为其包内路径），返回净化后的 HTML。"""
    parser = _Rewriter(html_path, has_file, url_for_view, url_for_res, report)
    parser.feed(html_text)
    parser.close()
    return "".join(parser.out)
