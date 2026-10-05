#!/usr/bin/env python3
"""冒烟测试：用 Flask 测试客户端验证上传、校验、重写与隔离。

运行：python3 tests/smoke_test.py
"""

import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import app, store  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")

PASS = 0
FAIL = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} {extra}")


def upload(client, zip_path: str):
    with open(zip_path, "rb") as fh:
        return client.post(
            "/upload",
            data={"file": (io.BytesIO(fh.read()), os.path.basename(zip_path))},
            content_type="multipart/form-data",
        )


def pkg_id_from_redirect(resp) -> str:
    loc = resp.headers["Location"]
    return loc.strip("/").split("/")[-1]


def main() -> None:
    app.config["TESTING"] = True
    client = app.test_client()

    print("== 首页 ==")
    resp = client.get("/")
    check("GET / 200", resp.status_code == 200)

    print("== nested_paths.zip 上传与预览 ==")
    before = len(store.list())
    resp = upload(client, os.path.join(SAMPLES, "nested_paths.zip"))
    check("上传 302", resp.status_code == 302, str(resp.status_code))
    check("入库恰好一个包", len(store.list()) == before + 1)
    pid = pkg_id_from_redirect(resp)

    resp = client.get(f"/pkg/{pid}/")
    check("包详情 200", resp.status_code == 200)
    body = resp.get_data(as_text=True)
    for entry in ("index.html", "pages/about.html", "pages/gallery/photos.html"):
        check(f"入口列出 {entry}", entry in body)

    resp = client.get(f"/pkg/{pid}/view/index.html")
    check("view index 200", resp.status_code == 200)
    html = resp.get_data(as_text=True)
    check("根相对样式表已重写", f"/pkg/{pid}/res/assets/css/site.css" in html)
    check("相对图片已重写", f"/pkg/{pid}/res/assets/img/logo.png" in html)
    check("页面链接已重写", f"/pkg/{pid}/view/pages/about.html" in html)
    check("根相对页面链接已重写", f"/pkg/{pid}/view/pages/gallery/photos.html" in html)
    csp = resp.headers.get("Content-Security-Policy", "")
    check("预览带 CSP sandbox", "sandbox" in csp and "default-src 'none'" in csp)

    resp = client.get(f"/pkg/{pid}/res/assets/css/site.css")
    check("css 200", resp.status_code == 200)
    css = resp.get_data(as_text=True)
    check("css url() 相对重写", f"/pkg/{pid}/res/assets/img/banner.jpg" in css)
    check("css url() 根相对重写", f"/pkg/{pid}/res/assets/img/logo.png" in css)

    resp = client.get(f"/pkg/{pid}/res/assets/css/pages/deep.css")
    css = resp.get_data(as_text=True)
    check("深层 css url() 重写", f"/pkg/{pid}/res/assets/img/banner.jpg" in css)

    resp = client.get(f"/pkg/{pid}/res/assets/img/logo.png")
    check("png 200 且为 PNG", resp.status_code == 200 and resp.data.startswith(b"\x89PNG"))
    resp = client.get(f"/pkg/{pid}/res/assets/img/banner.jpg")
    check("jpg 200 且为 JPEG", resp.status_code == 200 and resp.data.startswith(b"\xff\xd8"))

    resp = client.get(f"/pkg/{pid}/view/pages/gallery/photos.html")
    html = resp.get_data(as_text=True)
    check("深层页面样式表重写", f"/pkg/{pid}/res/assets/css/pages/deep.css" in html)
    check("深层页面相对图片重写", f"/pkg/{pid}/res/assets/img/photo1.png" in html)

    resp = client.get(f"/pkg/{pid}/view/../secret.html")
    check("view 路径越界 404", resp.status_code == 404, str(resp.status_code))
    resp = client.get(f"/pkg/{pid}/res/nope.png")
    check("不存在资源 404", resp.status_code == 404)

    print("== malicious_refs.zip 净化与报告 ==")
    resp = upload(client, os.path.join(SAMPLES, "malicious_refs.zip"))
    check("上传 302", resp.status_code == 302)
    pid = pkg_id_from_redirect(resp)

    resp = client.get(f"/pkg/{pid}/view/index.html")
    html = resp.get_data(as_text=True)
    check("无 <script", "<script" not in html.lower())
    check("无事件属性", "onclick" not in html and "onmouseover" not in html and "onload" not in html)
    check("无 <form", "<form" not in html.lower())
    check("无 <iframe", "<iframe" not in html.lower())
    check("无 <object/<embed", "<object" not in html.lower() and "<embed" not in html.lower())
    check("无 <base", "<base" not in html.lower())
    check("无 meta refresh", "http-equiv" not in html.lower())
    check("无 javascript: 属性", 'href="javascript:' not in html.lower())
    check("无 xlink:href", "xlink:href" not in html.lower())
    check("无 srcdoc", "srcdoc" not in html.lower())
    check("无 target 属性", " target=" not in html.lower())
    check("包外地址不出现在输出", "evil.example" not in html)
    check("正常页面链接保留", f"/pkg/{pid}/view/ok.html" in html)
    check("正常图片保留", f"/pkg/{pid}/res/ok.png" in html)
    check("@import 已移除", "@import" not in html)

    resp = client.get(f"/pkg/{pid}/res/style.css")
    css = resp.get_data(as_text=True)
    check("css @import 移除", "@import" not in css)
    check("css 包外 url 拦截", "evil.example" not in css)
    check("css 正常 url 重写", f"/pkg/{pid}/res/ok.png" in css)

    resp = client.get(f"/pkg/{pid}/")
    body = resp.get_data(as_text=True)
    pkg = store.get(pid)
    statuses = {r.status for r in pkg.report.entries}
    check("报告含缺失", "missing" in statuses)
    check("报告含越界", "out-of-bounds" in statuses)
    check("报告含包外", "external" in statuses)
    check("报告含不支持", "unsupported" in statuses)
    check("报告页面展示来源", "index.html" in body and "style.css" in body)
    check("报告页面展示目标", "evil.example" in body and "../../../etc/passwd" in body)
    missing_png = [r for r in pkg.report.entries if r.target == "missing.png"]
    check("missing.png 记为缺失且来源正确",
          len(missing_png) == 1 and missing_png[0].source == "index.html")

    print("== 结构非法的 ZIP 一律整体拒绝 ==")
    for name in ("reject_escape", "reject_absolute", "reject_dupe",
                 "reject_symlink", "reject_badtype", "reject_toomany"):
        n_before = len(store.list())
        resp = upload(client, os.path.join(SAMPLES, f"{name}.zip"))
        ok = resp.status_code == 302 and "error=" in resp.headers["Location"]
        check(f"{name} 被拒", ok, str(resp.status_code))
        check(f"{name} 不留半包", len(store.list()) == n_before)

    print("== 伪造超大包（解压总量超限） ==")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.html", "x" * (11 * 1024 * 1024))
    n_before = len(store.list())
    resp = client.post("/upload", data={"file": (buf.getvalue() and io.BytesIO(buf.getvalue()), "big.zip")},
                       content_type="multipart/form-data")
    check("超限被拒", "error=" in resp.headers["Location"])
    check("超限不留半包", len(store.list()) == n_before)

    print("== 非 UTF-8 HTML 拒绝 ==")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.html", b"<html>\xc3\x28</html>")
    n_before = len(store.list())
    resp = client.post("/upload", data={"file": (io.BytesIO(buf.getvalue()), "bad_utf8.zip")},
                       content_type="multipart/form-data")
    check("非 UTF-8 被拒", "error=" in resp.headers["Location"])
    check("非 UTF-8 不留半包", len(store.list()) == n_before)

    print("== 删除包 ==")
    resp = client.post(f"/pkg/{pid}/delete")
    check("删除 302", resp.status_code == 302)
    check("删除后详情 404", client.get(f"/pkg/{pid}/").status_code == 404)
    check("删除后预览 404", client.get(f"/pkg/{pid}/view/index.html").status_code == 404)

    print(f"\n通过 {PASS} 项，失败 {FAIL} 项")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
