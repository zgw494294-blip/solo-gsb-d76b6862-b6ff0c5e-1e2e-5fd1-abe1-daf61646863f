# 离线网页样张审阅台

上传 ZIP 样张包，在隔离沙盒中审阅其中的 HTML 页面。
Flask + 原生 HTML/CSS/JavaScript，无前端框架，全部数据保存在内存，不落地、不联网。

## 启动（单条命令）

```bash
docker compose up --build
```

然后打开 **http://localhost:8000**（端口 `8000`）。

本地运行（可选，需 Python 3.11+）：

```bash
pip install -r requirements.txt
python app.py            # 或：gunicorn -b 0.0.0.0:8000 app:app
```

## 使用

1. 首页选择 ZIP 上传；校验通过后跳转到包页面。
2. 左侧列出全部 HTML 入口，点击切换；右侧沙盒 iframe 中预览。
3. 页面下方列出「引用问题」（缺失 / 越界 / 包外，含来源与目标）与「已禁用的内容」。
4. 可直接试用 `samples/` 下的样例包。

## 包约束（上传即校验，失败整体拒绝，不留半包）

- 至多 **100 个文件**，解压总量 ≤ **10 MiB**，ZIP 体积 ≤ 20 MiB；
- 仅 **UTF-8 的 HTML/CSS** 与 **PNG/JPEG**（校验魔数），其余类型拒绝；
- 拒绝：绝对路径条目（含盘符）、`..` 逃逸包根的条目、符号链接、加密条目、
  规范化后重名（含大小写折叠重名）的条目；
- 包内没有 HTML 入口也视为失败。

## 引用解析规则

- 样式表、图片、页面链接、CSS `url()` 的**相对地址按所属文件目录解析**；
- **根相对地址**（`/…`）指向**包根**；
- 保留内联样式（`<style>` 与 `style=`），其中的 `url()` 同样重写；
- **不支持 `@import`**：移除并列入清单；
- `<base>` 被移除且**不参与解析**（解析基准始终是文件自身目录 / 包根）；
- 缺失、越界、包外引用：列出来源文件、位置、原始引用与解析目标，
  属性被移除或替换为空 `data:` 地址，**不会发起任何请求**（CSP 兜底）。

## 隔离设计

- 预览在 **sandbox iframe**（无任何 allow-* 令牌）中渲染：禁脚本、禁表单、
  禁弹窗、禁顶层跳转、禁同源访问，无法接触父页；
- 预览响应带严格 CSP：`default-src 'none'`，仅放行本域图片与样式，
  `form-action 'none'`、`base-uri 'none'`、`frame-ancestors 'self'`；
- HTML 清洗：删除 `<script>`、事件属性（`on*`）、`<form>`、`<iframe>` 等
  嵌套框架、`<object>/<embed>`、`<svg>`、`http-equiv` 刷新、`<base>`、注释；
- CSS 清洗：移除 `@import`、`expression()`、`behavior`/`-moz-binding`；
- 包 ID 为随机 128 位十六进制，URL 不可猜测：预览无法读取其它包；
  状态变更接口仅接受 POST，预览（脚本已禁）无法调用主应用接口；
- 资源路由只服务包内已登记文件（字典精确查找，路径穿越天然 404），
  HTML 不会经资源路由流出。

## 目录结构

```
app.py                 Flask 路由层（上传 / 包页面 / 预览 / 资源 / 删除）
review_core.py         核心：ZIP 校验、HTML/CSS 清洗、引用解析（无 Flask 依赖）
templates/             主应用页面模板（原生 HTML）
static/                主应用样式与少量原生 JS
samples/make_samples.py  样例生成脚本
samples/*.zip          演示样例（见下）
tests/test_review.py   单元测试（29 例）
Dockerfile / docker-compose.yml
```

## 样例

| 文件 | 说明 |
| --- | --- |
| `nested_site.zip` | 嵌套目录、相对/根相对引用、多页互链 —— 正常通过 |
| `malicious_refs.zip` | 脚本、事件属性、表单、iframe、base、外链/越界/缺失引用、`@import` —— 全部拦截并列清单 |
| `reject_traversal.zip` | 含 `../` 逃逸条目 —— 整体拒绝 |
| `reject_absolute.zip` | 含绝对路径条目 —— 整体拒绝 |
| `reject_symlink.zip` | 含符号链接条目 —— 整体拒绝 |
| `reject_dup.zip` | 规范化后重名条目 —— 整体拒绝 |

重新生成：`python samples/make_samples.py`

## 测试

```bash
python -m unittest discover -s tests -v
```

## 说明

- 包数据保存在进程内存中（最多 20 个，超出淘汰最旧），重启即清空；
- 生产部署如需多进程，请保持单 worker（gunicorn 已配置 `--workers 1 --threads 8`）。
