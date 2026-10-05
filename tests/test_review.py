#!/usr/bin/env python3
"""离线网页样张审阅台 —— 单元测试。

运行：python -m unittest discover -s tests -v
"""
import io
import os
import stat
import struct
import sys
import unittest
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as web                      # noqa: E402
from review_core import ZipRejected, load_package  # noqa: E402

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), 'samples')


def make_png(w=4, h=4, rgb=(1, 2, 3)):
    def chunk(typ, data):
        return (struct.pack('>I', len(data)) + typ + data
                + struct.pack('>I', zlib.crc32(typ + data) & 0xffffffff))
    ihdr = struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)
    raw = b''.join(b'\x00' + bytes(rgb) * w for _ in range(h))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', ihdr)
            + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b''))


PNG = make_png()
JPEG = b'\xff\xd8\xff\xe0' + b'\x00' * 32   # 测试用最小 JPEG 头


def make_zip(entries):
    """entries: (name, bytes|str[, external_attr])"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        for item in entries:
            name, data = item[0], item[1]
            attr = item[2] if len(item) > 2 else 0
            if isinstance(data, str):
                data = data.encode('utf-8')
            info = zipfile.ZipInfo(name)
            info.external_attr = attr
            zf.writestr(info, data)
    return buf.getvalue()


NESTED_ZIP = make_zip([
    ('index.html', '''<!doctype html><html><head>
        <link rel="stylesheet" href="/assets/site.css">
        <style>.a{background:url(img/a.png)}</style></head>
        <body><img src="img/a.png"><a href="pages/two.html">2</a></body></html>'''),
    ('pages/two.html', '''<html><body>
        <img src="../img/a.png"><a href="../index.html">back</a>
        <a href="/index.html#top">top</a></body></html>'''),
    ('assets/site.css', 'body{background:url(/img/a.png)}'),
    ('img/a.png', PNG),
])

EVIL_ZIP = make_zip([
    ('index.html', '''<!doctype html><html><head>
        <base href="https://evil.example/">
        <meta http-equiv="refresh" content="0;url=https://evil.example/">
        <link rel="stylesheet" href="s.css">
        <script>alert(1)</script></head>
        <body onclick="alert(1)">
        <img src="https://evil.example/x.png">
        <img src="../escape.png">
        <img src="missing.png">
        <img src="ok.png">
        <a href="javascript:alert(1)">j</a>
        <a href="https://evil.example/">e</a>
        <a href="/../../etc/passwd">p</a>
        <iframe src="https://evil.example/"></iframe>
        <form action="https://evil.example/"><input name="x"></form>
        <div style="background:url(https://evil.example/b.png)">d</div>
        </body></html>'''),
    ('s.css', '''@import url("https://evil.example/r.css");
        @import "missing.css";
        body{background:url(ok.png)}
        .a{background:url(https://evil.example/bg.png)}
        .b{background:url(../out.png)}
        .c{width:expression(alert(1));behavior:url(x.htc)}'''),
    ('ok.png', PNG),
])


class CoreTest(unittest.TestCase):
    """核心逻辑：ZIP 校验、清洗、引用解析。"""

    # ---- 正常解包与引用解析 ----
    def test_nested_ok(self):
        pkg = load_package(NESTED_ZIP, 'nested.zip')
        self.assertEqual(sorted(pkg.html_entries), ['index.html', 'pages/two.html'])
        html = pkg.files['index.html']['content'].decode()
        # 根相对样式表 -> 包根
        self.assertIn('/p/%s/asset/assets/site.css' % pkg.id, html)
        # 相对图片 -> 所属文件目录
        self.assertIn('/p/%s/asset/img/a.png' % pkg.id, html)
        # 内联 <style> 保留且 url() 已重写
        self.assertIn('<style>', html)
        self.assertIn('/p/%s/asset/img/a.png' % pkg.id, html)
        # 相对页面链接 -> 预览路由
        self.assertIn('/p/%s/view/pages/two.html' % pkg.id, html)
        # 无引用问题
        self.assertEqual(pkg.ref_issues, [])

    def test_base_ignored(self):
        z = make_zip([
            ('index.html', '<html><head><base href="https://evil.example/">'
                           '<link rel="stylesheet" href="a.css"></head>'
                           '<body><img src="i.png"></body></html>'),
            ('a.css', 'body{}'),
            ('i.png', PNG),
        ])
        pkg = load_package(z, 'b.zip')
        html = pkg.files['index.html']['content'].decode()
        self.assertNotIn('<base', html)
        self.assertNotIn('evil.example', html)
        self.assertIn('/p/%s/asset/a.css' % pkg.id, html)
        self.assertIn('/p/%s/asset/i.png' % pkg.id, html)

    def test_css_url_resolution(self):
        pkg = load_package(NESTED_ZIP, 'nested.zip')
        css = pkg.files['assets/site.css']['content'].decode()
        self.assertIn('/p/%s/asset/img/a.png' % pkg.id, css)

    # ---- 恶意内容清洗 ----
    def test_evil_sanitized(self):
        pkg = load_package(EVIL_ZIP, 'evil.zip')
        html = pkg.files['index.html']['content'].decode()
        # 危险内容全部移除
        for bad in ('<script', 'onclick', '<iframe', '<form', '<base',
                    'http-equiv="refresh"', 'javascript:'):
            self.assertNotIn(bad, html, bad)
        # 预览输出中不得出现任何包外地址
        self.assertNotIn('evil.example', html)
        # 正常图片保留并重写
        self.assertIn('/p/%s/asset/ok.png' % pkg.id, html)
        # CSS：@import 移除、外链/越界 url() 替换为 data:
        css = pkg.files['s.css']['content'].decode()
        self.assertNotIn('@import', css)
        self.assertNotIn('evil.example', css)
        self.assertNotIn('expression(', css)
        self.assertNotIn('behavior', css)
        self.assertIn('/p/%s/asset/ok.png' % pkg.id, css)
        self.assertIn('url("data:,")', css)
        # 问题清单：来源与目标齐全
        refs = pkg.ref_issues
        kinds = {(i['source'], i['status']) for i in refs}
        self.assertTrue(any('外部' in s or '包外' in s for _, s in kinds))
        self.assertTrue(any('不存在' in s for _, s in kinds))
        self.assertTrue(any('越界' in s for _, s in kinds))
        targets = [i['target'] for i in refs]
        self.assertIn('missing.png', targets)
        self.assertTrue(any('escape' in t or 'etc' in t or t == '—' for t in targets))
        # 每条问题都有来源文件
        self.assertTrue(all(i['source'] for i in refs))
        # 已禁用内容清单
        removed_what = ' '.join(i['where'] for i in pkg.removed_issues)
        self.assertIn('script', removed_what)
        self.assertIn('iframe', removed_what)
        self.assertIn('form', removed_what)

    def test_no_request_for_blocked_refs(self):
        """被拦截的引用不得出现在输出 URL 中（即不会发起请求）。"""
        pkg = load_package(EVIL_ZIP, 'evil.zip')
        for path, f in pkg.files.items():
            if f['type'] in ('html', 'css'):
                out = f['content'].decode()
                self.assertNotIn('evil.example', out, path)
                self.assertNotIn('../', out, path)   # 输出全部为包内绝对路径

    # ---- ZIP 拒绝 ----
    def assert_rejected(self, zbytes, needle=None):
        with self.assertRaises(ZipRejected) as cm:
            load_package(zbytes, 'x.zip')
        if needle:
            self.assertIn(needle, '；'.join(cm.exception.problems))

    def test_reject_traversal(self):
        self.assert_rejected(make_zip([
            ('index.html', 'ok'), ('../evil.html', 'x')]), '逃逸')

    def test_reject_absolute(self):
        self.assert_rejected(make_zip([
            ('index.html', 'ok'), ('/abs/evil.html', 'x')]), '绝对路径')

    def test_reject_drive_letter(self):
        self.assert_rejected(make_zip([
            ('index.html', 'ok'), ('C:/evil.html', 'x')]), '盘符')

    def test_reject_symlink(self):
        mode = (stat.S_IFLNK | 0o777) << 16
        self.assert_rejected(make_zip([
            ('index.html', 'ok'), ('link.html', 'index.html', mode)]), '符号链接')

    def test_reject_dup_normalized(self):
        self.assert_rejected(make_zip([
            ('index.html', 'ok'),
            ('a/./d.html', '1'), ('a/d.html', '2')]), '重名')

    def test_reject_dup_casefold(self):
        self.assert_rejected(make_zip([
            ('index.html', 'ok'), ('A.png', PNG), ('a.png', PNG)]), '重名')

    def test_reject_bad_type(self):
        self.assert_rejected(make_zip([
            ('index.html', 'ok'), ('notes.txt', 'x')]), '不支持')

    def test_reject_non_utf8(self):
        z = make_zip([('index.html', 'ok'), ('a.css', 'x')])
        # 手工构造 GBK 编码 CSS
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr('index.html', '<html>ok</html>')
            zf.writestr('a.css', 'body{content:"中文"}'.encode('gbk'))
        self.assert_rejected(buf.getvalue(), 'UTF-8')

    def test_reject_bad_png_magic(self):
        self.assert_rejected(make_zip([
            ('index.html', 'ok'), ('a.png', b'not-a-png')]), '魔数')

    def test_reject_too_many_files(self):
        entries = [('index.html', 'ok')]
        entries += [('f%03d.css' % i, 'x') for i in range(100)]
        self.assert_rejected(make_zip(entries), '100')

    def test_reject_too_large(self):
        big = make_png(1300, 1300, (7, 7, 7))
        entries = [('index.html', 'ok')]
        # 11 个 ~1MiB 的随机内容文件（不可压缩）
        import random
        rnd = random.Random(42)
        for i in range(11):
            data = bytes(rnd.getrandbits(8) for _ in range(1024 * 1024))
            entries.append(('b%d.png' % i, b'\x89PNG\r\n\x1a\n' + data))
        self.assert_rejected(make_zip(entries), '10 MiB')

    def test_reject_no_html(self):
        self.assert_rejected(make_zip([('a.css', 'x')]), 'HTML')

    def test_reject_not_zip(self):
        self.assert_rejected(b'not a zip at all', 'ZIP')

    # ---- 边界与细节 ----
    def test_exactly_100_files_ok(self):
        entries = [('index.html', 'ok')]
        entries += [('f%02d.css' % i, 'x') for i in range(99)]
        pkg = load_package(make_zip(entries), 'x.zip')
        self.assertEqual(len(pkg.files), 100)

    def test_fragment_and_link_to_asset(self):
        z = make_zip([
            ('index.html', '<html><body>'
                           '<a href="#sec">锚点</a>'
                           '<a href="pic.png">看图</a>'
                           '<a href="doc.html#top">带锚内链</a>'
                           '<h1 id="sec">s</h1></body></html>'),
            ('doc.html', '<html><body>d</body></html>'),
            ('pic.png', PNG),
        ])
        pkg = load_package(z, 'x.zip')
        html = pkg.files['index.html']['content'].decode()
        self.assertIn('href="#sec"', html)                      # 页内锚点保留
        self.assertIn('/p/%s/asset/pic.png' % pkg.id, html)     # 链接到图片 -> 资源路由
        self.assertIn('/p/%s/view/doc.html#top' % pkg.id, html) # 内链保留锚点

    def test_srcset_rewritten(self):
        z = make_zip([
            ('index.html', '<html><body>'
                           '<img srcset="a.png 1x, https://evil.example/b.png 2x, '
                           'missing.png 3x"></body></html>'),
            ('a.png', PNG),
        ])
        pkg = load_package(z, 'x.zip')
        html = pkg.files['index.html']['content'].decode()
        self.assertIn('/p/%s/asset/a.png 1x' % pkg.id, html)
        self.assertNotIn('evil.example', html)
        self.assertNotIn('missing.png 3x', html)
        self.assertEqual(len([i for i in pkg.ref_issues
                              if i['source'] == 'index.html']), 2)

    def test_utf8_bom_accepted(self):
        z = make_zip([
            ('index.html', '﻿<html><body>ok</body></html>'),
        ])
        pkg = load_package(z, 'x.zip')
        self.assertNotIn('﻿', pkg.files['index.html']['content'].decode())

    def test_percent_encoded_traversal(self):
        """%2e%2e 形式的越界引用同样被拦截。"""
        z = make_zip([
            ('index.html', '<html><body><img src="%2e%2e/secret.png"></body></html>'),
        ])
        pkg = load_package(z, 'x.zip')
        self.assertEqual(pkg.ref_issues[0]['status'], '越界（逃逸包根），已拦截')
        self.assertNotIn('secret', pkg.files['index.html']['content'].decode())

    def test_reject_encrypted_flag(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr('index.html', 'ok')
            zf.writestr('enc.css', 'x')
        data = bytearray(buf.getvalue())
        # 手工把两个条目的加密标志位置 1（本地头 + 中央目录）
        sig_local = data.rfind(b'PK\x03\x04')
        data[sig_local + 6] |= 0x1
        pos = 0
        while True:
            pos = data.find(b'PK\x01\x02', pos)
            if pos < 0:
                break
            data[pos + 8] |= 0x1
            pos += 4
        self.assert_rejected(bytes(data), '加密')


class WebTest(unittest.TestCase):
    """Flask 路由与隔离响应头。"""

    def setUp(self):
        web.PACKAGES.clear()
        self.client = web.app.test_client()

    def upload(self, zbytes, name='t.zip'):
        return self.client.post(
            '/upload', data={'file': (io.BytesIO(zbytes), name)},
            content_type='multipart/form-data', follow_redirects=False)

    def test_upload_and_browse(self):
        r = self.upload(NESTED_ZIP, 'nested.zip')
        self.assertEqual(r.status_code, 302)
        self.assertEqual(len(web.PACKAGES), 1)
        pkg_id = next(iter(web.PACKAGES))
        # 包页面
        r = self.client.get('/p/%s/' % pkg_id)
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertIn('index.html', body)
        self.assertIn('sandbox', body)          # iframe 沙盒属性
        # 预览
        r = self.client.get('/p/%s/view/index.html' % pkg_id)
        self.assertEqual(r.status_code, 200)
        csp = r.headers.get('Content-Security-Policy', '')
        self.assertIn("default-src 'none'", csp)
        self.assertIn("form-action 'none'", csp)
        # 资源
        r = self.client.get('/p/%s/asset/img/a.png' % pkg_id)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers['Content-Type'], 'image/png')
        r = self.client.get('/p/%s/asset/assets/site.css' % pkg_id)
        self.assertEqual(r.status_code, 200)
        self.assertIn('text/css', r.headers['Content-Type'])

    def test_upload_rejected_leaves_nothing(self):
        z = make_zip([('index.html', 'ok'), ('../evil.html', 'x')])
        r = self.upload(z)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(len(web.PACKAGES), 0)   # 失败不留半包
        r = self.client.get('/')
        self.assertIn('逃逸', r.get_data(as_text=True))

    def test_asset_cannot_serve_html(self):
        self.upload(NESTED_ZIP)
        pkg_id = next(iter(web.PACKAGES))
        r = self.client.get('/p/%s/asset/index.html' % pkg_id)
        self.assertEqual(r.status_code, 404)
        r = self.client.get('/p/%s/view/assets/site.css' % pkg_id)
        self.assertEqual(r.status_code, 404)

    def test_path_traversal_404(self):
        self.upload(NESTED_ZIP)
        pkg_id = next(iter(web.PACKAGES))
        r = self.client.get('/p/%s/asset/../index.html' % pkg_id)
        self.assertIn(r.status_code, (404, 308))  # 308: Werkzeug 规范化重定向
        r = self.client.get('/p/%s/asset/%%2e%%2e/index.html' % pkg_id)
        self.assertEqual(r.status_code, 404)

    def test_unknown_package_404(self):
        r = self.client.get('/p/%s/view/index.html' % ('0' * 32))
        self.assertEqual(r.status_code, 404)

    def test_preview_has_no_script(self):
        self.upload(EVIL_ZIP)
        pkg_id = next(iter(web.PACKAGES))
        r = self.client.get('/p/%s/view/index.html' % pkg_id)
        out = r.get_data(as_text=True)
        self.assertNotIn('<script', out)
        self.assertNotIn('evil.example', out)

    def test_delete_package(self):
        self.upload(NESTED_ZIP)
        pkg_id = next(iter(web.PACKAGES))
        r = self.client.post('/p/%s/delete' % pkg_id)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(len(web.PACKAGES), 0)
        r = self.client.get('/p/%s/' % pkg_id)
        self.assertEqual(r.status_code, 404)


class SampleFilesTest(unittest.TestCase):
    """samples/ 下的成品样例：正常样张通过，恶意样张全拦截，非法包全拒绝。"""

    def setUp(self):
        if not os.path.isdir(SAMPLES_DIR):
            self.skipTest('samples/ 不存在')
        web.PACKAGES.clear()
        self.client = web.app.test_client()

    def load(self, name):
        path = os.path.join(SAMPLES_DIR, name)
        if not os.path.exists(path):
            self.skipTest('缺少 %s，请先运行 samples/make_samples.py' % name)
        with open(path, 'rb') as f:
            return f.read()

    def test_nested_site(self):
        pkg = load_package(self.load('nested_site.zip'), 'nested_site.zip')
        self.assertEqual(len(pkg.html_entries), 3)
        self.assertEqual(pkg.ref_issues, [])
        html = pkg.files['pages/gallery.html']['content'].decode()
        self.assertIn('/p/%s/asset/assets/img/bg.png' % pkg.id, html)

    def test_malicious_refs(self):
        pkg = load_package(self.load('malicious_refs.zip'), 'malicious_refs.zip')
        self.assertGreaterEqual(len(pkg.ref_issues), 8)
        out = pkg.files['index.html']['content'].decode()
        self.assertNotIn('evil.example', out)
        self.assertNotIn('<script', out)

    def test_reject_samples(self):
        for name in ('reject_traversal.zip', 'reject_absolute.zip',
                     'reject_symlink.zip', 'reject_dup.zip'):
            with self.assertRaises(ZipRejected, msg=name):
                load_package(self.load(name), name)


if __name__ == '__main__':
    unittest.main()
