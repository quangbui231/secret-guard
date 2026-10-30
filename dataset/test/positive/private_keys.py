# PEM giả lập, không phải khóa mật mã hợp lệ
private_key_1 = """-----BEGIN RSA PRIVATE KEY-----
FAKE_RSA_PRIVATE_KEY_DATA_123456789
-----END RSA PRIVATE KEY-----"""

private_key_2 = """-----BEGIN PRIVATE KEY-----
FAKE_GENERIC_PRIVATE_KEY_DATA_987654321
-----END PRIVATE KEY-----"""

private_key_3 = """-----BEGIN EC PRIVATE KEY-----
FAKE_EC_PRIVATE_KEY_DATA_123456789
-----END EC PRIVATE KEY-----"""