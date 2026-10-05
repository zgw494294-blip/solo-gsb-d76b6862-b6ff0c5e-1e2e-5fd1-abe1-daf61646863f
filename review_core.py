"""离线网页样张审阅台 —— 核心逻辑（不依赖 Flask，可独立测试）。

职责：
  1. ZIP 校验与解包（数量 / 体积 / 类型 / 路径安全，失败整体拒绝）；
  2. HTML 清洗：删除脚本、事件属性、表单、嵌套框架等，重写包内引用；
  3. CSS 清洗：移除 @import 与脚本化特性，重写 url()；
  4. 引用解析：相对地址按所属文件目录解析，根相对地址指向包根，
     <base> 不参与解析；缺失 / 越界 / 包外引用记录来源与目标，且不发起请求。
"""
from __future__ import annotations

import html as html_mod
import io
import posixpath
import re
import stat
import time
import uuid
import zipfile
from collections import Counter
from html.parser import HTMLParser
from urllib.parse import quote, unquote

# ---------------------------------------------------------------- 限制与常量

MAX_FILES = 100                     # 包内文件数上限
MAX_TOTAL_BYTES = 10 * 1024 * 1024  # 解压总量上限 10 MiB
MAX_PROBLEMS = 15                   # 拒绝原因最多报告条数

HTML_EXT = {'.html', '.htm'}
CSS_EXT = {'.css'}
IMAGE_EXT = {'.png', '.jpg', '.jpeg'}
ALLOWED_EXT = HTML_EXT | CSS_EXT | IMAGE_EXT

IGNORED_NAMES = {'.ds_store'}           # 打包工具产生的噪音文件，忽略
IGNORED_PREFIXES = ('__macosx/',)

PNG_MAGIC = b'\x89PNG\r\n\x1a\n'
JPEG_MAGIC = b'\xff\xd8\xff'

IMAGE_MIME = {'.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg'}

SCHEME_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*:')

STATUS_TEXT = {
    'external': '包外地址，已拦截',
    'missing': '目标不存在，未请求',
    'escape': '越界（逃逸包根），已拦截',
    'anchor': '锚点引用在此处无效',
}


class ZipRejected(Exception):
    """ZIP 校验失败。problems 为全部拒绝原因；失败时不产生任何可预览内容。"""

    def __init__(self, problems):
        self.problems = list(problems)
        super().__init__('；'.join(self.problems))


# ---------------------------------------------------------------- 路径规范化

def normalize_rel(path):
    """规范化包内相对路径。返回 None 表示 .. 逃逸包根。"""
    parts = []
    for seg in path.split('/'):
        if seg in ('', '.'):
            continue
        if seg == '..':
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(seg)
    return '/'.join(parts)


def normalize_entry(name):
    """规范化 ZIP 条目名。返回 (norm_path|None, 问题描述|None)。

    norm_path 为 None 且无问题：该条目可忽略（目录等）。
    """
    if '\x00' in name:
        return None, '条目名含 NUL 字符：%r' % name
    n = name.replace('\\', '/')
    if n.startswith('/'):
        return None, '绝对路径条目：%s' % n
    if re.match(r'^[A-Za-z]:', n):
        return None, '绝对路径条目（盘符）：%s' % n
    parts = []
    for seg in n.split('/'):
        if seg in ('', '.'):
            continue
        if seg == '..':
            if not parts:
                return None, '条目逃逸包根：%s' % name
            parts.pop()
        else:
            parts.append(seg)
    if not parts:
        return None, None
    return '/'.join(parts), None


# ---------------------------------------------------------------- 引用解析

def resolve_reference(ref, base_dir, files):
    """把 HTML/CSS 中的引用解析为包内路径。

    返回 (status, target, fragment)：
      status: ok / empty / anchor / external / missing / escape
      target: status 为 ok/missing 时为规范化后的包内路径
    规则：相对地址按 base_dir（所属文件目录）解析；以 / 开头指向包根；
    带 scheme 或 // 开头的一律视为包外地址。<base> 不参与（调用方已移除）。
    """
    raw = (ref or '').strip()
    if not raw:
        return ('empty', None, '')
    if raw.startswith('#'):
        return ('anchor', None, raw[1:])
    if raw.startswith('//') or SCHEME_RE.match(raw):
        return ('external', None, '')
    path, frag = raw, ''
    if '#' in path:
        path, frag = path.split('#', 1)
    if '?' in path:
        path = path.split('?', 1)[0]
    path = unquote(path).replace('\\', '/')
    if path.startswith('/'):
        norm = normalize_rel(path[1:])
    else:
        norm = normalize_rel(('%s/%s' % (base_dir, path)) if base_dir else path)
    if norm is None:
        return ('escape', None, '')
    if not norm or norm not in files:
        return ('missing', norm or '/', '')
    return ('ok', norm, frag)


# ---------------------------------------------------------------- 构建上下文

class BuildContext:
    """一次解包构建的上下文：持有文件表、收集问题清单、生成包内 URL。"""

    def __init__(self, pkg_id, files):
        self.pkg_id = pkg_id
        self.files = files          # path -> {'type': 'html'|'css'|'image', ...}
        self.issues = []            # [{'kind','source','where','ref','target','status'}]

    # -- 问题记录 --
    def add_ref_issue(self, source, where, ref, target, status):
        self.issues.append({
            'kind': 'ref', 'source': source, 'where': where,
            'ref': ref, 'target': target, 'status': status,
        })

    def add_removed(self, source, what, count=1):
        self.issues.append({
            'kind': 'removed', 'source': source, 'where': what,
            'ref': '—', 'target': '—',
            'status': '已移除' if count == 1 else '已移除 ×%d' % count,
        })

    # -- URL 生成（绝对路径，iframe 内无需相对解析） --
    def asset_url(self, path):
        return '/p/%s/asset/%s' % (self.pkg_id, quote(path, safe='/'))

    def view_url(self, path):
        return '/p/%s/view/%s' % (self.pkg_id, quote(path, safe='/'))

    # -- 引用重写 --
    def rewrite_ref(self, ref, base_dir, want, where, source):
        """重写资源引用（图片 / 样式表 / CSS url()）。成功返回新 URL，失败返回 None。"""
        status, target, _frag = resolve_reference(ref, base_dir, self.files)
        if status == 'empty':
            return None
        if status != 'ok':
            self.add_ref_issue(source, where, (ref or '').strip() or '(空)',
                               target or '—', STATUS_TEXT.get(status, status))
            return None
        ftype = self.files[target]['type']
        ok = ((want == 'image' and ftype == 'image')
              or (want == 'css' and ftype == 'css')
              or (want == 'any' and ftype in ('image', 'css')))
        if not ok:
            self.add_ref_issue(source, where, ref.strip(), target,
                               '目标类型不允许（%s）' % ftype)
            return None
        return self.asset_url(target)

    def rewrite_link(self, ref, base_dir, source):
        """重写 <a href>：包内 HTML 走预览路由，其它包内文件走资源路由。"""
        raw = (ref or '').strip()
        if not raw:
            return None
        if raw.startswith('#'):
            return raw                      # 页内锚点原样保留
        status, target, frag = resolve_reference(raw, base_dir, self.files)
        if status != 'ok':
            self.add_ref_issue(source, '<a href>', raw, target or '—',
                               STATUS_TEXT.get(status, status))
            return None
        entry = self.files[target]
        url = self.view_url(target) if entry['type'] == 'html' else self.asset_url(target)
        if frag:
            url += '#' + quote(frag, safe='')
        return url


# ---------------------------------------------------------------- CSS 清洗

IMPORT_RE = re.compile(
    r'@import\s+(?:url\(\s*(["\']?)(.*?)\1\s*\)|(["\'])(.*?)\3)[^;]*(?:;|$)',
    re.IGNORECASE | re.DOTALL)
URL_RE = re.compile(
    r'url\(\s*(?:"([^"]*)"|\'([^\']*)\'|([^)]*?))\s*\)',
    re.IGNORECASE | re.DOTALL)
EXPRESSION_RE = re.compile(r'expression\s*\(', re.IGNORECASE)
BEHAVIOR_RE = re.compile(r'[^{};]*(?:-moz-binding|behavior)\s*:[^;}]*;?', re.IGNORECASE)


def sanitize_css(text, ctx, base_dir, source, where):
    """清洗 CSS 文本：移除 @import 与脚本化特性，重写 url() 指向包内资源。"""
    def drop_import(m):
        target = m.group(2) if m.group(2) is not None else m.group(4)
        ctx.add_ref_issue(source, where + ' 中的 @import',
                          (target or '').strip() or '(空)', '—',
                          '不支持 @import，已移除')
        return ''
    text = IMPORT_RE.sub(drop_import, text)

    def rewrite_url(m):
        ref = m.group(1)
        if ref is None:
            ref = m.group(2)
        if ref is None:
            ref = m.group(3) or ''
        new = ctx.rewrite_ref(ref, base_dir, 'any', where + ' 中的 url()', source)
        if new is None:
            return 'url("data:,")'   # 空 data: 地址，保证不发起任何网络请求
        return 'url("%s")' % new
    text = URL_RE.sub(rewrite_url, text)

    if EXPRESSION_RE.search(text):
        ctx.add_removed(source, where + ' 中的 expression()')
        text = EXPRESSION_RE.sub('blocked_expr(', text)
    if re.search(r'-moz-binding|behavior\s*:', text, re.IGNORECASE):
        ctx.add_removed(source, where + ' 中的 behavior/-moz-binding')
        text = BEHAVIOR_RE.sub('', text)
    return text


# ---------------------------------------------------------------- HTML 清洗

DROP_CONTENT_TAGS = {          # 连内容一起删除
    'script', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet',
    'svg', 'math', 'audio', 'video', 'source', 'track', 'portal', 'fencedframe',
}
DROP_TAGS_ONLY = {'form'}      # 只删标签，保留子内容
VOID_TAGS = {
    'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link',
    'meta', 'param', 'source', 'track', 'wbr',
}
DROP_ATTRS = {                 # 一律删除的属性
    'srcdoc', 'formaction', 'ping', 'download', 'target', 'manifest', 'poster',
}


class HtmlSanitizer(HTMLParser):
    """重写单个 HTML 文件：删除危险元素 / 属性，重写包内引用，拦截包外引用。"""

    def __init__(self, ctx, file_path):
        super().__init__(convert_charrefs=True)
        self.ctx = ctx
        self.file_path = file_path
        self.base_dir = posixpath.dirname(file_path)
        self.out = []
        self.drop_stack = []     # 正在丢弃的元素栈（处理嵌套）
        self.in_style = 0
        self.removed = Counter()

    # -- 结果 --
    def get_output(self):
        return ''.join(self.out)

    def note_removed(self, what):
        self.removed[what] += 1

    def flush_removed(self):
        for what, n in sorted(self.removed.items()):
            self.ctx.add_removed(self.file_path, what, n)

    # -- 标签 --
    def handle_starttag(self, tag, attrs):
        if self.drop_stack:
            if tag in DROP_CONTENT_TAGS:
                self.drop_stack.append(tag)
            return
        if tag in DROP_CONTENT_TAGS:
            self.note_removed('<%s> 元素' % tag)
            self.drop_stack.append(tag)
            return
        if tag in DROP_TAGS_ONLY:
            self.note_removed('<%s> 元素（保留子内容）' % tag)
            return
        if tag == 'base':
            self.note_removed('<base>（不参与解析）')
            return
        if tag == 'meta':
            amap = {k: (v or '') for k, v in attrs}
            he = amap.get('http-equiv', '').strip().lower()
            if he and he != 'content-type':
                self.note_removed('<meta http-equiv="%s">' % he)
                return
            self.emit(tag, attrs)
            return
        if tag == 'link':
            amap = {k: (v or '') for k, v in attrs}
            rels = set(amap.get('rel', '').lower().split())
            if 'stylesheet' not in rels:
                self.note_removed('<link rel="%s">' % (amap.get('rel') or '?'))
                return
            new = self.ctx.rewrite_ref(amap.get('href', ''), self.base_dir, 'css',
                                       '<link rel="stylesheet">', self.file_path)
            if new is None:
                return
            self.emit('link', [('rel', 'stylesheet'), ('href', new)])
            return
        if tag == 'style':
            self.in_style += 1
            self.out.append('<style>')
            return
        self.emit(tag, attrs)

    def handle_startendtag(self, tag, attrs):
        if self.drop_stack:
            return
        if tag in DROP_CONTENT_TAGS or tag in DROP_TAGS_ONLY or tag == 'base':
            self.note_removed('<%s/> 元素' % tag)
            return
        if tag == 'style':
            return
        if tag in ('meta', 'link'):
            self.handle_starttag(tag, attrs)
            return
        self.emit(tag, attrs)

    def handle_endtag(self, tag):
        if self.drop_stack:
            if tag == self.drop_stack[-1]:
                self.drop_stack.pop()
            return
        if tag in DROP_CONTENT_TAGS or tag in DROP_TAGS_ONLY or tag == 'base':
            return
        if tag == 'style':
            if self.in_style:
                self.in_style -= 1
            self.out.append('</style>')
            return
        if tag in VOID_TAGS:
            return
        self.out.append('</%s>' % tag)

    # -- 内容 --
    def handle_data(self, data):
        if self.drop_stack:
            return
        if self.in_style:
            self.out.append(sanitize_css(data, self.ctx, self.base_dir,
                                         self.file_path, '<style> 块'))
        else:
            self.out.append(html_mod.escape(data, quote=False))

    def handle_entityref(self, name):       # convert_charrefs=True 时一般不触发
        self.handle_data('&%s;' % name)

    def handle_charref(self, name):
        self.handle_data('&#%s;' % name)

    def handle_comment(self, data):
        pass                                # 注释一律丢弃（含条件注释风险）

    def handle_decl(self, decl):
        if decl.strip().lower().startswith('doctype'):
            self.out.append('<!doctype html>')

    def handle_pi(self, data):
        pass

    def unknown_decl(self, data):
        pass

    # -- 属性过滤与重写 --
    def emit(self, tag, attrs):
        out = ['<', tag]
        for name, value in attrs:
            if name.startswith('on'):
                self.note_removed('on* 事件属性')
                continue
            if name in DROP_ATTRS:
                self.note_removed('%s 属性' % name)
                continue
            if value is None:
                out.append(' %s' % name)
                continue
            if name == 'style':
                value = sanitize_css(value, self.ctx, self.base_dir,
                                     self.file_path, 'style 属性')
            elif name == 'href' and tag in ('a', 'area'):
                new = self.ctx.rewrite_link(value, self.base_dir, self.file_path)
                if new is None:
                    continue
                value = new
            elif name == 'src' and tag == 'img':
                new = self.ctx.rewrite_ref(value, self.base_dir, 'image',
                                           '<img src>', self.file_path)
                if new is None:
                    continue
                value = new
            elif name == 'srcset' and tag == 'img':
                new = self.rewrite_srcset(value)
                if new is None:
                    continue
                value = new
            elif name == 'background':
                new = self.ctx.rewrite_ref(value, self.base_dir, 'image',
                                           'background 属性', self.file_path)
                if new is None:
                    continue
                value = new
            elif (name in ('href', 'src', 'data', 'action', 'code', 'archive')
                    and tag not in ('a', 'area', 'img', 'link')):
                # 其余标签上的 URL 属性（对应元素多已被删除）一律移除；
                # a/area/img 的 href/src 已在上面重写，link 的 href 是重写后的值
                self.note_removed('<%s> 的 %s 属性' % (tag, name))
                continue
            out.append(' %s="%s"' % (name, html_mod.escape(value, quote=True)))
        out.append('>')
        self.out.append(''.join(out))

    def rewrite_srcset(self, value):
        parts = []
        for cand in value.split(','):
            cand = cand.strip()
            if not cand:
                continue
            bits = cand.split()
            url, desc = bits[0], ' '.join(bits[1:])
            new = self.ctx.rewrite_ref(url, self.base_dir, 'image',
                                       '<img srcset>', self.file_path)
            if new is None:
                continue
            parts.append((new + ' ' + desc).strip())
        return ', '.join(parts) if parts else None


# ---------------------------------------------------------------- 包对象

class Package:
    """一个已加载的样张包：全部内容在内存中，清洗完成后才允许预览。"""

    def __init__(self, pkg_id, name, files, html_entries, issues):
        self.id = pkg_id                 # 随机不可猜测，预览无法推算其它包地址
        self.name = name
        self.files = files               # path -> {'type','content'(bytes),'ext'?}
        self.html_entries = html_entries
        self.issues = issues
        self.created = time.strftime('%Y-%m-%d %H:%M:%S')

    @property
    def ref_issues(self):
        return [i for i in self.issues if i['kind'] == 'ref']

    @property
    def removed_issues(self):
        return [i for i in self.issues if i['kind'] == 'removed']


# ---------------------------------------------------------------- ZIP 解包

def load_package(zip_bytes, orig_name):
    """校验并解包。成功返回 Package；任何一步失败抛 ZipRejected，不留半包。"""
    problems = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        raise ZipRejected(['不是有效的 ZIP 文件'])

    raw = {}            # norm -> {'type','text'|'data'}
    seen = {}           # norm -> 原始条目名（规范化重名检测）
    seen_fold = {}      # casefold -> norm（大小写重名检测）
    total = 0
    nfiles = 0

    for info in zf.infolist():
        name = info.filename
        if len(problems) >= MAX_PROBLEMS:
            break
        mode = (info.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK:
            problems.append('符号链接条目：%s' % name)
            continue
        if info.flag_bits & 0x1:
            problems.append('加密条目：%s' % name)
            continue
        if info.is_dir() or name.endswith('/'):
            continue
        norm, prob = normalize_entry(name)
        if prob:
            problems.append(prob)
            continue
        if norm is None:
            continue
        low = norm.lower()
        if low in IGNORED_NAMES or any(low.startswith(p) for p in IGNORED_PREFIXES):
            continue
        nfiles += 1
        if nfiles > MAX_FILES:
            problems.append('文件条目超过 %d 个上限' % MAX_FILES)
            break
        ext = posixpath.splitext(norm)[1].lower()
        if ext not in ALLOWED_EXT:
            problems.append('不支持的文件类型：%s' % norm)
            continue
        if norm in seen:
            problems.append('规范化后重名：%r 与 %r' % (seen[norm], name))
            continue
        if low in seen_fold:
            problems.append('大小写规范化后重名：%s 与 %s' % (seen_fold[low], norm))
            continue
        try:
            data = zf.read(info)
        except Exception as exc:      # CRC 错误、加密、压缩流损坏等
            problems.append('读取条目失败：%s（%s）' % (norm, type(exc).__name__))
            continue
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            problems.append('解压总量超过 10 MiB 上限')
            break
        if ext in HTML_EXT or ext in CSS_EXT:
            try:
                text = data.decode('utf-8-sig')   # 允许并去除 BOM
            except UnicodeDecodeError:
                problems.append('非 UTF-8 编码：%s' % norm)
                continue
            raw[norm] = {'type': 'html' if ext in HTML_EXT else 'css', 'text': text}
        else:
            if ext == '.png' and not data.startswith(PNG_MAGIC):
                problems.append('PNG 魔数不符：%s' % norm)
                continue
            if ext in ('.jpg', '.jpeg') and not data.startswith(JPEG_MAGIC):
                problems.append('JPEG 魔数不符：%s' % norm)
                continue
            raw[norm] = {'type': 'image', 'data': data, 'ext': ext}
        seen[norm] = name
        seen_fold[low] = norm

    if problems:
        raise ZipRejected(problems)

    html_entries = sorted(p for p, f in raw.items() if f['type'] == 'html')
    if not html_entries:
        raise ZipRejected(['包内没有 HTML 入口文件'])

    # 二次加工：清洗与引用重写。全部成功后才算加载完成。
    pkg_id = uuid.uuid4().hex
    ctx = BuildContext(pkg_id, raw)
    files = {}
    for path in sorted(raw):
        f = raw[path]
        if f['type'] == 'html':
            san = HtmlSanitizer(ctx, path)
            san.feed(f['text'])
            san.close()
            san.flush_removed()
            files[path] = {'type': 'html', 'content': san.get_output().encode('utf-8')}
        elif f['type'] == 'css':
            cleaned = sanitize_css(f['text'], ctx, posixpath.dirname(path),
                                   path, 'CSS 文件')
            files[path] = {'type': 'css', 'content': cleaned.encode('utf-8')}
        else:
            files[path] = {'type': 'image', 'content': f['data'], 'ext': f['ext']}

    return Package(pkg_id, orig_name, files, html_entries, ctx.issues)
