#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import shlex
import solcx
import logging
import eth_utils
import subprocess

from web3 import Web3
from .settings import LOGGING_LEVEL
from web3.contract import ContractConstructor


#
def initialize_logger(name):
    logger = logging.getLogger(name)
    logger.title = lambda *a: logger.info(*[bold(x) for x in a])
    logger_error = logger.error
    logger.error = lambda *a: logger_error(*[red(bold(x)) for x in a])
    logger_warning = logger.warning
    logger.warning = lambda *a: logger_warning(*[red(bold(x)) for x in a])
    logger.setLevel(level=LOGGING_LEVEL)
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    return logger


def bold(x):
    return "".join(['\033[1m', x, '\033[0m']) if isinstance(x, str) else x


def red(x):
    return "".join(['\033[91m', x, '\033[0m']) if isinstance(x, str) else x


def code_bool(value: bool):
    return str(int(value)).zfill(64)


def code_uint(value):
    return hex(value).replace("0x", "").zfill(64)


def code_int(value):
    return hex(value).replace("0x", "").zfill(64)


def code_address(value):
    return value.zfill(64)


def code_bytes(value):
    return value.ljust(64, "0")


def code_type(value, type):
    if type == "bool":
        return code_bool(value)
    elif type.startswith("uint"):
        return code_uint(value)
    elif type.startswith("int"):
        return code_int(value)
    elif type == "address":
        return code_address(value)
    elif type.startswith("bytes"):
        return code_bytes(value)
    else:
        raise Exception()


def run_command(cmd):
    FNULL = open(os.devnull, 'w')
    p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=FNULL)
    return p.communicate()[0]


# 传入编译器版本、evm版本、源码文件(.sol)编译生成
def compile(solc_version, evm_version, source_code_file):
    # 初始化out变量为None，它将用来存储编译的输出结果
    out = None
    source_code = ""
    # 读取source_code_file指定的文件内容到source_code变量中
    with open(source_code_file, 'r') as file:
        source_code = file.read()
    try:
        # 检查solc_version是否以"v"开头，如果不是，则添加"v"前缀
        if not str(solc_version).startswith("v"):
            solc_version = "v" + str(solc_version.truncate())
        # 检查指定的solc_version是否已经安装，如果没有，则调用solcx.install_solc安装该版本的编译器。
        if not solc_version in solcx.get_installed_solc_versions():
            solcx.install_solc(solc_version)
        # 设置solcx（Solidity编译器的Python接口）使用特定的编译器版本。
        solcx.set_solc_version(solc_version, True)
        # 调用solcx.compile_standard方法来编译源代码
        out = solcx.compile_standard({
            'language': 'Solidity',
            'sources': {source_code_file: {'content': source_code}},
            'settings': {
                "optimizer": {
                    "enabled": True,
                    "runs": 200
                },
                "evmVersion": evm_version,
                # 指定输出哪些内容
                "outputSelection": {
                    source_code_file: {
                        "*":
                            [
                                "abi",
                                "evm.deployedBytecode",
                                "evm.bytecode.object",
                                "evm.legacyAssembly",
                            ],
                    }
                }
            }
        }, allow_paths='.')
    except Exception as e:
        print("Error: Solidity compilation failed!")
        print(e.message)
    return out


# 解析智能合约的ABI（Application Binary Interface，应用程序二进制接口），
# 从而构建一个接口映射，该映射包含智能合约中函数的签名和构造函数的参数信息。
def get_interface_from_abi(abi):
    interface = {}
    # 遍历ABI列表中的每个条目，每一条都是一个描述合约中一个函数或构造函数的字典
    for field in abi:
        # 检查当前条目的类型是否为'function'，如果是，则处理这个函数条目
        if field['type'] == 'function':
            # 从字典中提取函数名称
            function_name = field['name']
            function_inputs = []
            # 开始构建函数的签名字符串，首先添加函数名和一个左括号
            signature = function_name + '('
            # 遍历函数的所有参数
            for i in range(len(field['inputs'])):
                # 从当前函数的参数列表中获取参数类型
                input_type = field['inputs'][i]['type']
                # 将参数类型添加到function_inputs列表中
                function_inputs.append(input_type)
                # 在签名字符串中添加参数类型，并在参数之间添加逗号分隔符（除了最后一个参数）
                signature += input_type
                if i < len(field['inputs']) - 1:
                    signature += ','
            # 在参数列表结束后添加右括号来完成函数的签名字符串
            signature += ')'
            # 使用Web3.sha3对签名字符串进行哈希处理，然后取前4个字节并转换为十六进制字符串。
            # 这是函数选择器（在以太坊中用来标识和调用函数的）的计算方式。
            hash = Web3.sha3(text=signature)[0:4].hex()
            interface[hash] = function_inputs
        # 如果是构造函数
        elif field['type'] == 'constructor':
            function_inputs = []
            # 与函数条目类似，遍历构造函数的参数，构建参数类型列表。
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                function_inputs.append(input_type)
            # 将构造函数的参数类型列表存储在interface字典中，键为'constructor'。
            interface['constructor'] = function_inputs
    # 确保interface字典中有一个键为'fallback'的条目。
    # 如果ABI中没有指定回退函数，就添加一个空列表作为值。
    if not "fallback" in interface:
        interface["fallback"] = []
    return interface


# 从智能合约的ABI中提取函数的签名，并创建一个从函数的四字节选择器到其完整签名字符串的映射。
def get_function_signature_mapping(abi):
    mapping = {}
    # 遍历ABI中的每个元素。每个元素通常是一个字典，描述了智能合约的一个函数或构造函数。
    for field in abi:
        # 如果元素的类型是'function'，则进入处理逻辑。
        if field['type'] == 'function':
            # 获取函数名称，并开始构建函数签名。
            # 函数签名是由函数名称和括号内的参数类型列表组成的字符串。
            function_name = field['name']
            signature = function_name + '('
            # 遍历函数参数，将每个参数的类型追加到签名字符串中，并在参数之间插入逗号。
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                signature += input_type
                if i < len(field['inputs']) - 1:
                    signature += ','
            # 在参数列表结束后添加右括号来完成函数签名的构建。
            signature += ')'
            # 使用Web3.sha3函数对完整的函数签名进行SHA3哈希处理，然后取哈希值的前4个字节，并将它们转换为十六进制字符串。
            # 这个十六进制字符串是函数选择器，用于在以太坊的EVM中识别和调用函数。
            hash = Web3.sha3(text=signature)[0:4].hex()
            # 将函数选择器与其完整签名字符串的映射存储到mapping字典中
            mapping[hash] = signature
    # 检查mapping字典中是否有'fallback'函数的条目。
    # 如果没有，则添加一个条目，键是'fallback'，值也是'fallback'。
    if not "fallback" in mapping:
        mapping["fallback"] = "fallback"
    return mapping


# 去除Solidity编译器附加在合约字节码末尾的Swarm哈希
def remove_swarm_hash(bytecode):
    # 检查bytecode参数是否为字符串类型，确保函数处理的是正确的数据类型。
    if isinstance(bytecode, str):
        # 检查字节码字符串是否以"0029"结尾。这是Swarm哈希结尾的标识符之一
        if bytecode.endswith("0029"):
            # 如果字节码以"0029"结尾，使用正则表达式匹配Swarm哈希的特定模式，并将其从字节码中移除。
            bytecode = re.sub(r"a165627a7a72305820\S{64}0029$", "", bytecode)
        # 检查字节码字符串是否以"0033"结尾。这是Swarm哈希结尾的另一个标识符。
        if bytecode.endswith("0033"):
            bytecode = re.sub(r"5056fe.*?0033$", "5056", bytecode)
    return bytecode


# 分析智能合约的编译后字节码，提取出所有的程序计数器（PC）位置和JUMPI（跳转）指令的位置。
# 这个函数对于静态分析和理解智能合约的控制流非常有用，特别是在确定合约逻辑中可能的跳转点和执行路径时。
# 通过知道所有的JUMPI指令位置，可以帮助分析合约的分支逻辑。
def get_pcs_and_jumpis(bytecode):
    # 首先调用remove_swarm_hash函数去除字节码中的Swarm哈希（如果存在的话），
    # 然后删除字节码字符串前的"0x"（如果存在的话），将剩余的十六进制字符串转换为字节序列。
    bytecode = bytes.fromhex(remove_swarm_hash(bytecode).replace("0x", ""))
    # 初始化计数器i和两个空列表
    # pcs（用于存储程序计数器位置）和
    # jumpis（用于存储JUMPI指令位置）。
    i = 0
    pcs = []
    jumpis = []
    # 循环遍历字节码的每个字节
    while i < len(bytecode):
        # 读取当前位置i的操作码（opcode）
        opcode = bytecode[i]
        # 将当前位置i添加到pcs列表中，因为每个字节都是一个可能的程序计数器位置。
        pcs.append(i)
        # 如果操作码等于87，这表示遇到了JUMPI指令。
        if opcode == 87:  # JUMPI
            # 如果是JUMPI指令，将当前位置的十六进制表示添加到jumpis列表中。
            jumpis.append(hex(i))
        # 如果操作码在96到127之间，这表示遇到了PUSH指令（压栈操作）。
        if 96 <= opcode <= 127:  # PUSH
            # 计算PUSH指令将要推入栈的数据的大小，然后增加计数器i，跳过这些字节，因为这些字节是数据，不是指令。
            size = opcode - 96 + 1
            i += size
        # 每次循环结束时递增计数器i以遍历下一个字节。
        i += 1
    # 如果pcs列表为空，表示没有找到任何程序计数器位置，将其初始化为包含0的列表。
    if len(pcs) == 0:
        pcs = [0]
    return pcs, jumpis


# 将栈上的值转换为整数。
# 如果栈值已经是整数类型，则直接返回该值；
# 如果是字节序列，则将字节序列按大端序转换为整数。
def convert_stack_value_to_int(stack_value):
    if stack_value[0] == int:
        return stack_value[1]
    elif stack_value[0] == bytes:
        return int.from_bytes(stack_value[1], "big")
    else:
        raise Exception("Error: Cannot convert stack value to int. Unknown type: " + str(stack_value[0]))


# 将栈上的值转换为十六进制字符串。
# 如果值是整数，则将其转换为十六进制字符串，并确保它前面填充零，总长度为64位。
# 如果值是字节序列，也将其转换为填充零的64位十六进制字符串。
def convert_stack_value_to_hex(stack_value):
    if stack_value[0] == int:
        return hex(stack_value[1]).replace("0x", "").zfill(64)
    elif stack_value[0] == bytes:
        return stack_value[1].hex().zfill(64)
    else:
        raise Exception("Error: Cannot convert stack value to hex. Unknown type: " + str(stack_value[0]))


# 检查给定的值是否为固定整数类型。
def is_fixed(value):
    return isinstance(value, int)


# 将一个序列按指定长度分割成多个部分
def split_len(seq, length):
    return [seq[i:i + length] for i in range(0, len(seq), length)]


# 格式化并打印模糊测试生成的单个解决方案（即交易）的详细信息。
# 参数：
# logger：日志记录器对象
# individual_solution：代表个体解决方案的列表
# color：可选。表示的是命令行的字体颜色
# function_signature_mapping：函数签名映射
# transaction_index：交易索引
def print_individual_solution_as_transaction(logger, individual_solution, color="", function_signature_mapping={},
                                             transaction_index=None):
    # 遍历individual_solution列表中的每个元素。每个元素都代表一个交易。
    for index, input in enumerate(individual_solution):
        # 从当前元素中获取交易信息，存储在transaction字典中。
        transaction = input["transaction"]
        # 检查交易是否有目标地址。
        if not transaction["to"] is None:
            # 获取交易数据的前缀（函数选择器），用于识别交易调用的是哪个函数。
            if transaction["data"].startswith("0x"):
                hash = transaction["data"][0:10]
            else:
                hash = transaction["data"][0:8]
            # 如果只有一个交易或者指定了交易索引，且索引为0，则会特别打印该交易。
            if len(individual_solution) == 1 or (transaction_index is not None and transaction_index == 0):
                # 使用logger的title方法打印交易信息。
                # 如果函数选择器在映射中，则打印对应的函数签名，
                # 否则只打印"Transaction:"。
                if hash in function_signature_mapping:
                    logger.title(color + "Transaction - " + function_signature_mapping[hash] + ":")
                else:
                    logger.title(color + "Transaction:")
            else:
                # 如果有多个交易，则为每个交易打印编号和信息。
                if hash in function_signature_mapping:
                    logger.title(
                        color + "Transaction " + str(index + 1) + " - " + function_signature_mapping[hash] + ":")
                else:
                    logger.title(color + "Transaction " + str(index + 1) + ":")
            logger.title(color + "-----------------------------------------------------")
            logger.title(color + "From:      " + transaction["from"])
            logger.title(color + "To:        " + str(transaction["to"]))
            logger.title(color + "Value:     " + str(transaction["value"]) + " Wei")
            logger.title(color + "Gas Limit: " + str(transaction["gaslimit"]))
            i = 0
            for data in split_len("0x" + transaction["data"].replace("0x", ""), 42):
                if i == 0:
                    logger.title(color + "Input:     " + str(data))
                else:
                    logger.title(color + "           " + str(data))
                i += 1
            logger.title(color + "-----------------------------------------------------")
            # 如果提供了transaction_index，且当前交易的索引超出了指定的索引，则终止循环。
            # 这允许只打印到指定的交易索引处的交易信息。
            # if transaction_index is not None and index + 1 > transaction_index:
            #     break


def normalize_32_byte_hex_address(value):
    as_bytes = eth_utils.to_bytes(hexstr=value)
    return eth_utils.to_normalized_address(as_bytes[-20:])


def get_constructor_abi(contract_abi):
    candidates = [abi for abi in contract_abi if abi["type"] == "constructor"]
    if len(candidates) == 1:
        return candidates[0]
    elif len(candidates) == 0:
        return None
    elif len(candidates) > 1:
        raise ValueError("Found multiple constructors.")
    return None


# bytecode:原字节码
# *args:参数
# 将参数编码为abi格式后附在字节码后
def encode_abi(abi, bytecode, *args, **kwargs):
    return ContractConstructor(Web3, abi, bytecode, *args, **kwargs).data_in_transaction
