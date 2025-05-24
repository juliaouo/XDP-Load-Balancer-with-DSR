# server.py
from flask import Flask, Response, request
import os
import time
import psutil
import threading
from flask import stream_with_context

app = Flask(__name__)
cpu_times = []
latency_records = []

@app.route("/")
def hello():
    return "OK\n"

@app.route("/cpu")
def cpu():
    # 模擬計算密集：大量隨機哈希
    start = time.time()
    x = b""
    for _ in range(200000):
        x = os.urandom(64)
    latency = (time.time() - start) * 1000  # ms
    latency_records.append(latency)
    if len(latency_records) > 10:
        latency_records.pop(0)
    return "cpu done\n"

@app.route("/io")
def io_load():
    def gen():
        # 每次都重新生成，避免重复引用同一块内存
        for _ in range(5):
            yield os.urandom(1024*1024)
    # 把 generator 包裹进 stream_with_context，这样每次 yield 都有活跃的 request/app context
    return Response(
        stream_with_context(gen()),
        mimetype="application/octet-stream"
    )

@app.route("/metrics")
def metrics():
    # 計算過去 1 秒的平均 CPU 負載 (%)
    cpu_percent = psutil.cpu_percent(interval=0.1)

    # 最近 10 筆 latency 平均值
    recent = latency_records[-10:] if len(latency_records) >= 10 else latency_records
    avg_latency = sum(recent) / len(recent) if recent else 0.0

    return f"cpu={cpu_percent:.2f}\nlatency={avg_latency:.2f}ms\n"

if __name__ == "__main__":
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host="0.0.0.0", port=80)
