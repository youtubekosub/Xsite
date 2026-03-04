import hmac
import hashlib
import base64
import time
import os
from flask import Flask, request, redirect, abort, render_template
from dotenv import load_dotenv

# .envがあれば読み込む（ローカル用）
load_dotenv()

app = Flask(__name__)

# Renderの環境変数から取得。generateValue: true を使う場合はRender側で自動設定されます
SECRET_KEY = os.environ.get('SECRET_KEY', 'default-key-3.14159').encode()
LINK_DURATION = 600 

def generate_secure_url(target_url):
    expires = str(int(time.time()) + LINK_DURATION)
    b64_url = base64.urlsafe_b64encode(target_url.encode()).decode()
    data_to_sign = f"{b64_url}{expires}".encode()
    signature = hmac.new(SECRET_KEY, data_to_sign, hashlib.sha256).hexdigest()[:16]
    return f"/goto?u={b64_url}&e={expires}&s={signature}"

@app.route('/')
def index():
    query = request.args.get('q', '')
    results = []
    if query:
        mock_data = [
            {"title": f"{query} - 匿名検索結果", "url": f"https://duckduckgo.com/?q={query}", "desc": "HMAC署名によって保護されたアクセスです。"},
            {"title": "Privacy Tools", "url": "https://www.privacytools.io/", "desc": "プライバシーを守るためのツール集。"}
        ]
        for res in mock_data:
            res['proxy_url'] = generate_secure_url(res['url'])
            results.append(res)
    return render_template('index.html', query=query, results=results)

@app.route('/goto')
def goto():
    b64_url = request.args.get('u')
    expires = request.args.get('e')
    signature = request.args.get('s')
    if not all([b64_url, expires, signature]):
        abort(400)
    data_to_verify = f"{b64_url}{expires}".encode()
    expected_sig = hmac.new(SECRET_KEY, data_to_verify, hashlib.sha256).hexdigest()[:16]
    if not hmac.compare_digest(signature, expected_sig) or int(time.time()) > int(expires):
        return "Invalid or Expired Link", 403
    try:
        target_url = base64.urlsafe_b64decode(b64_url).decode()
    except:
        abort(400)
    response = redirect(target_url)
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

# この部分はローカル実行用。Render（gunicorn）では無視されます。
if __name__ == '__main__':
    # Render環境では PORT 環境変数が渡されます。デフォルトは5000。
    port = int(os.environ.get('PORT', 5000))
    # host='0.0.0.0' が必須です
    app.run(host='0.0.0.0', port=port)

