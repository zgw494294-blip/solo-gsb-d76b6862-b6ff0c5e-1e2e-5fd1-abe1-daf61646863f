"""离线网页样张审阅台 —— Flask 入口。

路由：
  GET  /                        上传表单 + 已加载包列表
  POST /upload                  校验并加载 ZIP（失败整体拒绝，不留半包）
  GET  /pkg/<pid>/              包详情：HTML 入口、引用报告、隔离预览框
  POST /pkg/<pid>/delete        移除包
  GET  /pkg/<pid>/view/<path>   重写后的 HTML（仅包内页面，强 CSP + sandbox）
  GET  /pkg/<pid>/res/<path>    包内资源（CSS 已重写 / PNG / JPEG）

隔离设计：
  - 预览页以 iframe sandbox="" 加载，且自身响应头带 CSP sandbox 指令，
    脚本、表单、弹窗、顶层跳转、跨包请求全部被封死；
  - 预览页所有引用在上传时已静态重写为本包 /pkg/<id>/... 地址，
    包外 / 缺失 / 越界引用只进报告，不会出现在输出里，因此不会发起请求。
"""

from __future__ import annotations

import posixpath

from flask import Flask, Response, abort, redirect, render_template, request, url_for

from proofing.package import MAX_FILES, MAX_TOTAL_BYTES, PackageError, load_package
from proofing.refs import STATUS_LABELS
from proofing.store import PackageStore

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 上传的 ZIP 本体上限（压缩态）

store = PackageStore()

# 预览页 CSP：默认全部禁止，仅放行本源的样式与图片；sandbox 指令与
# iframe 的 sandbox 属性取交集，双保险。
_PREVIEW_CSP = (
    "sandbox; "
    "default-src 'none'; "
    "img-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'none'; "
    "connect-src 'none'; "
    "font-src 'none'; "
    "media-src 'none'; "
    "object-src 'none'; "
    "child-src 'none'; "
    "form-action 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'self'"
)

_APP_CSP = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'"

_IMAGE_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
}


@app.after_request
def add_security_headers(resp: Response) -> Response:
    if "Content-Security-Policy" not in resp.headers:
        resp.headers["Content-Security-Policy"] = _APP_CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


def _preview_response(body: str | bytes, content_type: str) -> Response:
    resp = Response(body, content_type=content_type)
    resp.headers["Content-Security-Policy"] = _PREVIEW_CSP
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/")
def index():
    return render_template(
        "index.html",
        packages=store.list(),
        max_files=MAX_FILES,
        max_total_mb=MAX_TOTAL_BYTES // (1024 * 1024),
        error=request.args.get("error"),
    )


@app.post("/upload")
def upload():
    f = request.files.get("file")
    if f is None or not f.filename:
        return redirect(url_for("index", error="请选择要上传的 ZIP 文件"))
    blob = f.read()
    try:
        pkg = load_package(f.filename, blob)
    except PackageError as exc:
        # 校验失败：什么都不入库，不存在可预览的半包
        return redirect(url_for("index", error=str(exc)))
    store.add(pkg)
    return redirect(url_for("package_page", pkg_id=pkg.id))


@app.get("/pkg/<pkg_id>/")
def package_page(pkg_id: str):
    pkg = store.get(pkg_id)
    if pkg is None:
        abort(404)
    return render_template(
        "package.html",
        pkg=pkg,
        status_labels=STATUS_LABELS,
    )


@app.post("/pkg/<pkg_id>/delete")
def delete_package(pkg_id: str):
    store.remove(pkg_id)
    return redirect(url_for("index"))


@app.get("/pkg/<pkg_id>/view/<path:path>")
def view_page(pkg_id: str, path: str):
    pkg = store.get(pkg_id)
    if pkg is None:
        abort(404)
    body = pkg.rendered_html.get(path)
    if body is None:
        abort(404)
    return _preview_response(body, "text/html; charset=utf-8")


@app.get("/pkg/<pkg_id>/res/<path:path>")
def view_resource(pkg_id: str, path: str):
    pkg = store.get(pkg_id)
    if pkg is None:
        abort(404)
    ext = posixpath.splitext(path)[1].lower()
    if ext == ".css":
        css = pkg.rendered_css.get(path)
        if css is None:
            abort(404)
        return _preview_response(css, "text/css; charset=utf-8")
    if ext in _IMAGE_TYPES:
        data = pkg.files.get(path)
        if data is None:
            abort(404)
        return _preview_response(data, _IMAGE_TYPES[ext])
    abort(404)


@app.errorhandler(413)
def too_large(_):
    return redirect(url_for("index", error="上传的 ZIP 本体超过 32 MiB 限制"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
