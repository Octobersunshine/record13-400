import hashlib
import os
import tempfile
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
            result = calculate_file_hash(f, ['md5', 'sha1', 'sha256'])

        assert result['md5'] == expected_md5, f'MD5 不匹配: {result["md5"]} != {expected_md5}'
        assert result['sha1'] == expected_sha1, f'SHA1 不匹配: {result["sha1"]} != {expected_sha1}'
        assert result['sha256'] == expected_sha256, f'SHA256 不匹配: {result["sha256"]} != {expected_sha256}'

        print('✅ calculate_file_hash 函数测试通过')
        print()
    finally:
        os.unlink(temp_path)


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
    try:
        test_api()
    except requests.exceptions.ConnectionError:
        print('⚠️  无法连接到 API，请先启动服务: python app.py')
        print('   本地函数测试已通过 ✓')
