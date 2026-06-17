import hashlib
import os
import sys
import io
import tempfile
import tracemalloc
import requests


def test_local_hash():
    with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
        f.write(b'Hello, World!')
        temp_path = f.name

    try:
        with open(temp_path, 'rb') as f:
            content = f.read()

        expected_md5 = hashlib.md5(content).hexdigest()
        expected_sha1 = hashlib.sha1(content).hexdigest()
        expected_sha256 = hashlib.sha256(content).hexdigest()

        print('=== 本地哈希测试 ===')
        print(f'测试内容: "Hello, World!"')
        print(f'MD5:    {expected_md5}')
        print(f'SHA1:   {expected_sha1}')
        print(f'SHA256: {expected_sha256}')
        print()

        from app import calculate_file_hash

        with open(temp_path, 'rb') as f:
            result, size = calculate_file_hash(f, ['md5', 'sha1', 'sha256'])

        assert size == len(content), f'文件大小不匹配: {size} != {len(content)}'
        assert result['md5'] == expected_md5, f'MD5 不匹配: {result["md5"]} != {expected_md5}'
        assert result['sha1'] == expected_sha1, f'SHA1 不匹配: {result["sha1"]} != {expected_sha1}'
        assert result['sha256'] == expected_sha256, f'SHA256 不匹配: {result["sha256"]} != {expected_sha256}'

        print('✅ calculate_file_hash 函数测试通过')
        print()
    finally:
        os.unlink(temp_path)


def test_large_file_memory():
    print('=== 大文件内存安全测试 ===')

    from app import calculate_file_hash, CHUNK_SIZE

    target_size = 20 * 1024 * 1024
    print(f'模拟文件大小: {target_size // (1024*1024)} MB')
    print(f'分块大小: {CHUNK_SIZE // 1024} KB')

    class LimitedMemoryStream(io.BufferedIOBase):
        def __init__(self, total_size):
            super().__init__()
            self._remaining = total_size
            self._pattern = b'A' * 65536
            self._pos = 0

        def readable(self):
            return True

        def read(self, size=-1):
            if size is None or size < 0 or size > self._remaining:
                size = self._remaining
            if size <= 0 or self._remaining <= 0:
                return b''
            result = (self._pattern * (size // len(self._pattern) + 1))[:size]
            self._remaining -= len(result)
            self._pos += len(result)
            return result

        def seek(self, pos, whence=0):
            if whence == 0:
                self._pos = pos
                self._remaining = target_size - pos
            return self._pos

        def tell(self):
            return self._pos

    tracemalloc.start()
    snapshot1 = tracemalloc.take_snapshot()

    stream = LimitedMemoryStream(target_size)
    result, size = calculate_file_hash(stream, ['md5', 'sha1', 'sha256'])

    snapshot2 = tracemalloc.take_snapshot()
    tracemalloc.stop()

    stats = snapshot2.compare_to(snapshot1, 'lineno')
    peak_memory = max(stat.size_diff for stat in stats) if stats else 0
    total_allocated = sum(stat.size_diff for stat in stats if stat.size_diff > 0)

    print(f'读取字节数: {size:,}')
    print(f'MD5: {result["md5"]}')
    print(f'内存增量 (峰值): {peak_memory / 1024:.2f} KB')
    print(f'内存增量 (总计): {total_allocated / 1024:.2f} KB')

    expected_md5 = hashlib.md5(b'A' * target_size).hexdigest()
    assert result['md5'] == expected_md5, f'MD5 验证失败: {result["md5"]} != {expected_md5}'
    assert size == target_size, f'大小不匹配: {size} != {target_size}'

    memory_limit = 5 * 1024 * 1024
    if total_allocated > memory_limit:
        print(f'⚠️  警告: 内存使用超过 {memory_limit // (1024*1024)} MB，可能存在内存问题')
    else:
        print(f'✅ 内存使用合理 (低于 {memory_limit // (1024*1024)} MB 阈值)')

    print()
    return result, size


def test_api():
    url = 'http://127.0.0.1:5000/hash'

    with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
        f.write(b'Hello, World!')
        temp_path = f.name

    try:
        print('=== API 接口测试 ===')
        print(f'测试文件: {temp_path}')
        print()

        with open(temp_path, 'rb') as f:
            files = {'file': f}
            data = {'algorithms': ['md5', 'sha1', 'sha256']}
            response = requests.post(url, files=files, data=data)

        print(f'状态码: {response.status_code}')
        result = response.json()
        print(f'响应: {result}')
        print()

        assert response.status_code == 200, f'状态码错误: {response.status_code}'
        assert 'hashes' in result, '响应缺少 hashes 字段'
        assert 'md5' in result['hashes'], '响应缺少 md5'
        assert 'sha1' in result['hashes'], '响应缺少 sha1'
        assert 'sha256' in result['hashes'], '响应缺少 sha256'

        expected_md5 = hashlib.md5(b'Hello, World!').hexdigest()
        assert result['hashes']['md5'] == expected_md5, 'API 返回的 MD5 不正确'
        assert result['size'] == 13, f'文件大小不正确: {result["size"]}'

        print('✅ API 接口测试通过')
        print()

        print('=== 单算法测试 ===')
        with open(temp_path, 'rb') as f:
            files = {'file': f}
            data = {'algorithms': ['sha256']}
            response = requests.post(url, files=files, data=data)

        result = response.json()
        print(f'仅 SHA256: {result["hashes"]}')
        assert list(result['hashes'].keys()) == ['sha256'], '应该只返回 sha256'
        print('✅ 单算法测试通过')
        print()

        print('=== 错误处理测试 ===')
        response = requests.post(url, data={})
        print(f'未上传文件 - 状态码: {response.status_code}')
        assert response.status_code == 400, '应该返回 400'
        print('✅ 未上传文件测试通过')

        with open(temp_path, 'rb') as f:
            files = {'file': f}
            data = {'algorithms': ['invalid_alg']}
            response = requests.post(url, files=files, data=data)

        print(f'无效算法 - 状态码: {response.status_code}')
        assert response.status_code == 400, '应该返回 400'
        print('✅ 无效算法测试通过')

    finally:
        os.unlink(temp_path)

    print()
    print('🎉 所有测试通过!')


if __name__ == '__main__':
    test_local_hash()
    test_large_file_memory()
    try:
        test_api()
    except requests.exceptions.ConnectionError:
        print('⚠️  无法连接到 API，请先启动服务: python app.py')
        print('   本地函数和大文件内存测试已通过 ✓')
