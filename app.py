#!/usr/bin/env python3
"""离线网页样张审阅台 —— Flask 路由层。

启动：python app.py  （或 gunicorn -b 0.0.0.0:8000 app:app）
"""
from __future__ import annotations

import os
import posixpath
import threading
from collections import OrderedDict

from flask import (Flask, Response, abort, flash, redirect, render_template,
                   request, url_for)

from review_core import (IMAGE_MIME, MAX_FILES, MAX_TOTAL_BYTES, Package,
                         ZipRejected, load_package)

MAX_ZIP_BYTES = 20 * 1024 * 1024   # 上传 ZIP 体积上限（解压后仍受 10 MiB 限制）
MAX_PACKAGES = 20                  # 内存中最多保留的包数，超出淘汰最旧

# 预览页：禁脚本、禁表单、禁弹窗、禁顶层跳转，仅允许本域样式与图片
PREVIEW_CSP = (
    "default-src 'none'; img-src 'self'; style-src 'self' 'unsafe-inline'; "
    "font-src 'none'; connect-src 'none'; frame-src 'none'; child-src 'none'; "
    "worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'self'"
)
# 包内资源（CSS / 图片）：不允许任何主动内容
ASSET_CSP = (
    "default-src 'none'; img-src 'self'; style-src 'self' 'unsafe-inline'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
# 主应用页面
APP_CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; "
    "frame-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config['MAX_CONTENT_LENGTH'] = MAX_ZIP_BYTES + 1024 * 1024

PACKAGES: 'OrderedDict[str, Package]' = OrderedDict()
LOCK = threading.Lock()


def get_package(pkg_id):
    pkg = PACKAGES.get(pkg_id)
    if pkg is None:
        abort(404)
    return pkg


def secure_response(content, content_type, csp):
    resp = Response(content, content_type=content_type)
    resp.headers['Content-Security-Policy'] = csp
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.after_request
def add_security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('Referrer-Policy', 'no-referrer')
    resp.headers.setdefault('Content-Security-Policy', APP_CSP)
    return resp


# ---------------------------------------------------------------- 页面

@app.route('/')
def index():
    with LOCK:
        packages = list(PACKAGES.values())
    return render_template('index.html', packages=packages,
                           max_packages=MAX_PACKAGES,
                           max_files=MAX_FILES,
                           max_total_mib=MAX_TOTAL_BYTES // (1024 * 1024))


@app.post('/upload')
def upload():
    f = request.files.get('file')
    if not f or not f.filename:
        flash('请选择要上传的 ZIP 文件', 'error')
        return redirect(url_for('index'))
    data = f.read(MAX_ZIP_BYTES + 1)
    if len(data) > MAX_ZIP_BYTES:
        flash('ZIP 体积超过 20 MiB 上限，已拒绝', 'error')
        return redirect(url_for('index'))
    try:
        pkg = load_package(data, f.filename)
    except ZipRejected as exc:
        flash('已拒绝该 ZIP，未保留任何内容：', 'error')
        for p in exc.problems:
            flash(p, 'error')
        return redirect(url_for('index'))
    except Exception:
        app.logger.exception('解包失败')
        flash('解包失败，未保留任何内容', 'error')
        return redirect(url_for('index'))
    with LOCK:
        PACKAGES[pkg.id] = pkg
        while len(PACKAGES) > MAX_PACKAGES:
            PACKAGES.popitem(last=False)
    flash('已加载：%s（%d 个文件，%d 个 HTML 入口）'
          % (pkg.name, len(pkg.files), len(pkg.html_entries)), 'ok')
    return redirect(url_for('package_page', pkg_id=pkg.id))


@app.route('/p/<pkg_id>/')
def package_page(pkg_id):
    pkg = get_package(pkg_id)
    entry = request.args.get('entry', '')
    if entry not in pkg.files or pkg.files[entry]['type'] != 'html':
        entry = pkg.html_entries[0]
    return render_template('package.html', pkg=pkg, entry=entry)


@app.post('/p/<pkg_id>/delete')
def delete_package(pkg_id):
    with LOCK:
        PACKAGES.pop(pkg_id, None)
    flash('已删除该包', 'ok')
    return redirect(url_for('index'))


# ---------------------------------------------------------------- 预览与资源

@app.route('/p/<pkg_id>/view/<path:fname>')
def view_file(pkg_id, fname):
    """清洗后的 HTML 预览，供沙盒 iframe 加载。"""
    pkg = get_package(pkg_id)
    entry = pkg.files.get(fname)
    if entry is None or entry['type'] != 'html':
        abort(404)
    return secure_response(entry['content'], 'text/html; charset=utf-8', PREVIEW_CSP)


@app.route('/p/<pkg_id>/asset/<path:fname>')
def asset_file(pkg_id, fname):
    """包内资源：CSS（已清洗）与 PNG/JPEG 原始字节。HTML 一律 404。"""
    pkg = get_package(pkg_id)
    entry = pkg.files.get(fname)
    if entry is None or entry['type'] == 'html':
        abort(404)
    if entry['type'] == 'css':
        return secure_response(entry['content'], 'text/css; charset=utf-8', ASSET_CSP)
    mime = IMAGE_MIME.get(entry.get('ext') or posixpath.splitext(fname)[1].lower(),
                          'application/octet-stream')
    return secure_response(entry['content'], mime, ASSET_CSP)


@app.errorhandler(413)
def too_large(_exc):
    flash('上传体积超过上限（ZIP ≤ 20 MiB），已拒绝', 'error')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
