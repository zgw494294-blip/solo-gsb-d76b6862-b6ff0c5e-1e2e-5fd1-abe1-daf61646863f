FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# 先装依赖，充分利用构建缓存
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 应用代码与资源
COPY app.py ./
COPY proofing ./proofing
COPY templates ./templates
COPY static ./static
COPY samples ./samples

EXPOSE 8000

# 单 worker 多线程：包数据保存在进程内存中
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", "app:app"]
