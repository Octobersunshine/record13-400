import hashlib
import gc
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, jsonify, render_template_string
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

CHUNK_SIZE = 1024 * 1024

PARALLEL_THRESHOLD = 2

ALLOWED_ALGORITHMS = {'md5', 'sha1', 'sha256'}

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件哈希服务</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 40px;
            max-width: 600px;
            width: 100%;
        }
        h1 {
            color: #333;
            margin-bottom: 8px;
            font-size: 28px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .upload-area {
            border: 2px dashed #667eea;
            border-radius: 12px;
            padding: 40px 20px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            background: #f8f9ff;
        }
        .upload-area:hover, .upload-area.dragover {
            border-color: #764ba2;
            background: #f0f2ff;
        }
        .upload-area input[type="file"] {
            display: none;
        }
        .upload-icon {
            font-size: 48px;
            color: #667eea;
            margin-bottom: 16px;
        }
        .upload-text {
            color: #333;
            font-size: 16px;
            margin-bottom: 8px;
        }
        .upload-hint {
            color: #999;
            font-size: 13px;
        }
        .algorithms {
            margin: 24px 0;
        }
        .algorithms label {
            display: inline-flex;
            align-items: center;
            margin-right: 20px;
            cursor: pointer;
            color: #555;
            font-size: 14px;
        }
        .algorithms input[type="checkbox"] {
            margin-right: 6px;
            width: 16px;
            height: 16px;
            cursor: pointer;
        }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        button:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4);
        }
        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        .result {
            margin-top: 24px;
            padding: 20px;
            background: #f8f9ff;
            border-radius: 8px;
            display: none;
        }
        .result.show {
            display: block;
            animation: slideIn 0.3s ease;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .result h3 {
            color: #333;
            margin-bottom: 12px;
            font-size: 16px;
        }
        .hash-item {
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-radius: 6px;
            border-left: 3px solid #667eea;
        }
        .hash-label {
            color: #666;
            font-size: 12px;
            text-transform: uppercase;
            margin-bottom: 4px;
        }
        .hash-value {
            color: #333;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            word-break: break-all;
            user-select: all;
        }
        .error {
            margin-top: 24px;
            padding: 16px;
            background: #fee;
            color: #c33;
            border-radius: 8px;
            border-left: 3px solid #c33;
            display: none;
        }
        .error.show {
            display: block;
        }
        .loading {
            text-align: center;
            padding: 20px;
            color: #667eea;
            display: none;
        }
        .loading.show {
            display: block;
        }
        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 12px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .selected-file {
            margin-top: 12px;
            padding: 10px;
            background: #e8ebff;
            border-radius: 6px;
            color: #667eea;
            font-size: 13px;
            display: none;
        }
        .selected-file.show {
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📂 文件哈希服务</h1>
        <p class="subtitle">支持 MD5、SHA1、SHA256 哈希计算</p>

        <div class="upload-area" id="uploadArea">
            <input type="file" id="fileInput">
            <div class="upload-icon">📁</div>
            <div class="upload-text">点击选择文件 或 拖拽文件到此处</div>
            <div class="upload-hint">最大支持 100MB</div>
        </div>
        <div class="selected-file" id="selectedFile"></div>

        <div class="algorithms">
            <label><input type="checkbox" name="alg" value="md5" checked> MD5</label>
            <label><input type="checkbox" name="alg" value="sha1" checked> SHA1</label>
            <label><input type="checkbox" name="alg" value="sha256" checked> SHA256</label>
        </div>

        <button id="submitBtn" disabled>计算哈希值</button>

        <div class="loading" id="loading">
            <div class="spinner"></div>
            <div>正在计算哈希值...</div>
        </div>

        <div class="error" id="error"></div>

        <div class="result" id="result">
            <h3>✅ 计算结果</h3>
            <div id="hashResults"></div>
        </div>
    </div>

    <script>
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const selectedFile = document.getElementById('selectedFile');
        const submitBtn = document.getElementById('submitBtn');
        const loading = document.getElementById('loading');
        const error = document.getElementById('error');
        const result = document.getElementById('result');
        const hashResults = document.getElementById('hashResults');

        let currentFile = null;

        uploadArea.addEventListener('click', () => fileInput.click());

        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            if (e.dataTransfer.files.length > 0) {
                handleFile(e.dataTransfer.files[0]);
            }
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleFile(e.target.files[0]);
            }
        });

        function handleFile(file) {
            currentFile = file;
            selectedFile.textContent = `已选择: ${file.name} (${formatFileSize(file.size)})`;
            selectedFile.classList.add('show');
            submitBtn.disabled = false;
            error.classList.remove('show');
            result.classList.remove('show');
        }

        function formatFileSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
            return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
        }

        submitBtn.addEventListener('click', async () => {
            if (!currentFile) return;

            const algorithms = Array.from(document.querySelectorAll('input[name="alg"]:checked'))
                .map(cb => cb.value);

            if (algorithms.length === 0) {
                showError('请至少选择一种哈希算法');
                return;
            }

            const formData = new FormData();
            formData.append('file', currentFile);
            algorithms.forEach(alg => formData.append('algorithms', alg));

            loading.classList.add('show');
            submitBtn.disabled = true;
            error.classList.remove('show');
            result.classList.remove('show');

            try {
                const response = await fetch('/hash', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (response.ok) {
                    showResults(data);
                } else {
                    showError(data.error || '计算失败');
                }
            } catch (e) {
                showError('网络错误，请稍后重试');
            } finally {
                loading.classList.remove('show');
                submitBtn.disabled = false;
            }
        });

        function showResults(data) {
            hashResults.innerHTML = '';
            for (const [alg, hash] of Object.entries(data.hashes)) {
                const div = document.createElement('div');
                div.className = 'hash-item';
                div.innerHTML = `
                    <div class="hash-label">${alg.toUpperCase()}</div>
                    <div class="hash-value">${hash}</div>
                `;
                hashResults.appendChild(div);
            }
            const fileInfo = document.createElement('div');
            fileInfo.style.marginTop = '12px';
            fileInfo.style.fontSize = '12px';
            fileInfo.style.color = '#999';
            fileInfo.textContent = `文件名: ${data.filename} | 大小: ${formatFileSize(data.size)}`;
            hashResults.appendChild(fileInfo);
            result.classList.add('show');
        }

        function showError(msg) {
            error.textContent = '❌ ' + msg;
            error.classList.add('show');
        }
    </script>
</body>
</html>
'''


_HASHER_MAP = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
}


def _create_hashers(algorithms):
    hashers = {}
    for alg in algorithms:
        factory = _HASHER_MAP.get(alg)
        if factory is None:
            raise ValueError(f'不支持的算法: {alg}')
        hashers[alg] = factory()
    return hashers


def calculate_file_hash(stream, algorithms, chunk_size=CHUNK_SIZE):
    hashers = _create_hashers(algorithms)

    total_size = 0
    chunk = stream.read(chunk_size)
    while chunk:
        total_size += len(chunk)
        for hasher in hashers.values():
            hasher.update(chunk)
        del chunk
        gc.collect()
        chunk = stream.read(chunk_size)

    result = {alg: hasher.hexdigest() for alg, hasher in hashers.items()}
    return result, total_size


def calculate_file_hash_parallel(stream, algorithms, chunk_size=CHUNK_SIZE, max_workers=None):
    hashers = _create_hashers(algorithms)

    if max_workers is None:
        max_workers = len(hashers)

    hasher_list = list(hashers.values())

    def _update_all(chunk_bytes):
        for h in hasher_list:
            h.update(chunk_bytes)

    total_size = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        chunk = stream.read(chunk_size)
        while chunk:
            total_size += len(chunk)
            futures = [executor.submit(h.update, chunk) for h in hasher_list]
            for f in futures:
                f.result()
            del chunk
            del futures
            gc.collect()
            chunk = stream.read(chunk_size)

    result = {alg: hasher.hexdigest() for alg, hasher in hashers.items()}
    return result, total_size


def calculate_file_hash_auto(stream, algorithms, chunk_size=CHUNK_SIZE):
    if len(algorithms) >= PARALLEL_THRESHOLD:
        return calculate_file_hash_parallel(stream, algorithms, chunk_size)
    return calculate_file_hash(stream, algorithms, chunk_size)


@app.route('/', methods=['GET'])
def index():
    return render_template_string(HTML_TEMPLATE)


def _validate_and_get_request():
    if 'file' not in request.files:
        return None, None, None, (jsonify({'error': '未上传文件'}), 400)

    file_storage = request.files['file']
    if file_storage.filename == '':
        return None, None, None, (jsonify({'error': '未选择文件'}), 400)

    algorithms = request.form.getlist('algorithms')
    if not algorithms:
        algorithms = ['md5', 'sha1', 'sha256']

    invalid_algs = [alg for alg in algorithms if alg not in ALLOWED_ALGORITHMS]
    if invalid_algs:
        return None, None, None, (jsonify({
            'error': f'不支持的算法: {", ".join(invalid_algs)}。支持的算法: md5, sha1, sha256'
        }), 400)

    return file_storage, algorithms, None, None


@app.route('/hash', methods=['POST'])
def hash_endpoint():
    file_storage, algorithms, _, error = _validate_and_get_request()
    if error:
        return error

    try:
        filename = secure_filename(file_storage.filename) or file_storage.filename
        stream = file_storage.stream
        try:
            stream.seek(0)
        except Exception:
            pass

        hashes, file_size = calculate_file_hash_auto(stream, algorithms)

        return jsonify({
            'filename': filename,
            'size': file_size,
            'hashes': hashes,
            'parallel': len(algorithms) >= PARALLEL_THRESHOLD
        })
    except MemoryError:
        return jsonify({'error': '内存不足，文件过大'}), 413
    except Exception as e:
        return jsonify({'error': f'处理文件时出错: {str(e)}'}), 500


@app.route('/hash/parallel', methods=['POST'])
def hash_parallel_endpoint():
    file_storage, algorithms, _, error = _validate_and_get_request()
    if error:
        return error

    try:
        filename = secure_filename(file_storage.filename) or file_storage.filename
        stream = file_storage.stream
        try:
            stream.seek(0)
        except Exception:
            pass

        import time
        t0 = time.perf_counter()
        hashes, file_size = calculate_file_hash_parallel(stream, algorithms)
        elapsed = time.perf_counter() - t0

        return jsonify({
            'filename': filename,
            'size': file_size,
            'hashes': hashes,
            'parallel': True,
            'elapsed_seconds': round(elapsed, 4)
        })
    except MemoryError:
        return jsonify({'error': '内存不足，文件过大'}), 413
    except Exception as e:
        return jsonify({'error': f'处理文件时出错: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
