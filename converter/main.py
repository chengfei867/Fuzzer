def to_bytes32_array(strings):
    bytes32_array = []
    for string in strings:
        # 将字符串转换为字节，然后截断或填充到 32 字节
        bytes32 = string.encode('utf-8')[:32]  # 截断到 32 字节
        bytes32 = bytes32.ljust(32, b'\0')     # 使用空字节填充到 32 字节
        bytes32_array.append(bytes32)
    return bytes32_array

# 示例使用
string_array = ["提案1", "提案2", "提案3"]
bytes32_array = to_bytes32_array(string_array)

# 打印结果
print(bytes32_array)