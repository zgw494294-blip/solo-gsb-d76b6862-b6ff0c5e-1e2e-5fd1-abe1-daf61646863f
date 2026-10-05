# 离线网页样张审阅台

用 Flask + 原生 HTML/CSS/JavaScript 实现的离线样张审阅工具：上传 ZIP 后列出其中的
HTML 入口，在隔离预览框中逐页浏览，并对缺失、越界、包外引用进行审计。

## 启动

```bash
docker compose up --build
```

- 地址：<http://localhost:8000>
- 端口：`8000`（在 `docker-compose.yml` 的 `ports` 中可改）

停止：`docker compose down`。包数据保存在进程内存中，重启即清空。

本地开发（不用 Docker）：

```bash
pip install -r requirements.txt
python app.py            # 同样监听 0.0.0.0:8000
```

## 使用

1. 首页选择 ZIP 上传；校验通过后跳转到包详情页。
2. 左侧列出全部 HTML 入口，点击即在右侧隔离预览框中打开。
3. 左侧下方是该包的「问题引用」报告：每条含来源文件、出现位置、原始目标与问题类型。
4. 包只保存在内存中，可在详情页或首页删除。

`samples/` 目录附带可直接上传的示例包：

| 文件 | 说明 |
| --- | --- |
| `nested_paths.zip` | 嵌套路径样张：相对/根相对引用、深层 CSS 的 `url()`、内嵌样式 |
| `malicious_refs.zip` | 恶意引用样张：包外地址、`../` 越界、脚本、表单、`@import` 等 |
| `reject_escape.zip` 等 | 结构非法（逃逸包根、绝对路径、规范化重名、符号链接、非法类型、超限），应被整体拒绝 |

样张源文件展开在 `samples/src/`，执行 `python3 samples/make_samples.py` 可重新生成全部 ZIP。

## 规则与限制

### 包校验（任一不满足即整体拒绝，不留下可预览的半包）

- 至多 **100 个文件**，解压总量不超过 **10 MiB**（上传的 ZIP 本体不超过 32 MiB）；
- 仅支持 **UTF-8 的 HTML/CSS** 与 **PNG/JPEG**（校验魔数），其余文件类型拒绝；
- 拒绝含**绝对路径**（`/...`、`C:\...`）、**反斜杠**、经规范化后**逃逸包根**（`..`）的条目；
- 拒绝**符号链接**及其他非常规文件类型；
- 拒绝**规范化后重名**的条目（如 `a/x.html` 与 `a/./x.html`）。

### 引用解析

- HTML 的样式表（`<link>`）、图片（`<img>`/`srcset`）、页面链接（`<a>`/`<area>`）、
  内联 `style` 属性与 `<style>` 块中的 `url()`，以及 CSS 文件的 `url()`，
  一律**按所属文件所在目录**解析；**根相对地址**（`/x/y.png`）指向**包根**；
- 保留内嵌样式；**不支持 `@import`**（整条移除并记录）；`<base>` 直接丢弃，**不改变解析基准**；
- 命中的包内文件改写为 `/pkg/<id>/...` 隔离地址；**缺失、越界、包外**引用列入报告
  （来源 + 目标），输出中不含这些地址，**不会发起请求**。

### 隔离与禁用项

- 预览页在 `<iframe sandbox="">` 中加载，且响应头带 `Content-Security-Policy: sandbox; default-src 'none'; …`，
  双重封禁：脚本、事件属性（`on*`）、表单、嵌套框架（`iframe`/`frame`/`object`/`embed`）、
  `meta` 刷新、`srcdoc`、弹窗与顶层跳转全部禁用；
- 预览只能加载**本包**资源：所有引用在上传时已静态重写为本包地址，包外/越界目标不会出现在输出中；
  无脚本即无法调用主应用接口、读取其他包或触碰父页面；
- 主应用接口仅 `POST /upload` 与 `POST /pkg/<id>/delete` 有副作用，且预览内容无法发起此类请求。

## 测试

```bash
python3 tests/smoke_test.py
```

覆盖：上传与入口列表、相对/根相对/深层路径重写、净化（脚本/事件/表单/框架/`<base>`/刷新）、
报告内容、六类非法包的拒绝与「不留半包」、超限与非 UTF-8 拒绝、删除。

## 目录结构

```
app.py                  Flask 入口与路由
proofing/
  refs.py               引用解析与报告
  rewriter_html.py      HTML 重写与净化
  rewriter_css.py       CSS url() 重写、@import 移除
  package.py            ZIP 校验与包构建（全量校验通过才入库）
  store.py              内存包存储
templates/ static/      主应用界面（原生 HTML/CSS/JS）
samples/                示例包与生成脚本
tests/smoke_test.py     冒烟测试
Dockerfile / docker-compose.yml
```
