# server.py
from flask import Flask, Response
import os

app = Flask(__name__)

@app.route("/")
def hello():
    return "OK\n"

@app.route("/cpu")
def cpu():
    # 模拟计算密集：大量随机哈希
    x = b""
    for _ in range(200000):
        x = os.urandom(64)
    return "cpu done\n"

@app.route("/io")
def io_load():
    # 模拟网络密集：5MB 随机数据
    chunk = os.urandom(1024*1024)
    def gen():
        for _ in range(5):
            yield chunk
    return Response(gen(), mimetype="application/octet-stream")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
