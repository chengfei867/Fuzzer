#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pickle
import logging

from eth import Chain, constants
from eth.chains.mainnet import (
    MAINNET_GENESIS_HEADER,
    HOMESTEAD_MAINNET_BLOCK,
    TANGERINE_WHISTLE_MAINNET_BLOCK,
    SPURIOUS_DRAGON_MAINNET_BLOCK,
    BYZANTIUM_MAINNET_BLOCK,
    PETERSBURG_MAINNET_BLOCK
)
from eth.constants import ZERO_ADDRESS, CREATE_CONTRACT_ADDRESS
from eth.db.atomic import AtomicDB
from eth.db.backends.memory import MemoryDB
from eth.rlp.accounts import Account
from eth.rlp.headers import BlockHeader
from eth.tools.logging import DEBUG2_LEVEL_NUM
from eth.validation import validate_uint256
from eth.vm.spoof import SpoofTransaction
from eth_utils import to_canonical_address, decode_hex, encode_hex
from web3 import HTTPProvider
from web3 import Web3

from .storage_emulation import (
    FrontierVMForFuzzTesting,
    HomesteadVMForFuzzTesting,
    TangerineWhistleVMForFuzzTesting,
    SpuriousDragonVMForFuzzTesting,
    ByzantiumVMForFuzzTesting,
    PetersburgVMForFuzzTesting
)

from utils import settings
from utils.utils import initialize_logger


# InstrumentedEVM类是一个对Ethereum虚拟机（EVM）进行了自定义扩展，使其适用于特定的模糊测试场景。
# 属性：
# w3: 使用Web3与以太坊节点通信的接口。
# chain: 配置了多个不同版本的EVM，包括从Frontier到Petersburg的主要版本。
# logger: 用于日志记录的工具。
# accounts: 存储模拟账户地址的列表。
# snapshot: 存储EVM状态的快照。
# vm: 当前活动的虚拟机实例。
class InstrumentedEVM:
    # InstrumentedEVM类的__init__方法用于初始化类实例，
    # 配置以太坊链（Ethereum chain）和不同版本的以太坊虚拟机（EVM），
    # 设置日志记录器，并初始化账户列表等。
    # 接受可选的以太坊节点IP地址（eth_node_ip）和端口号（eth_node_port）作为参数
    def __init__(self, eth_rpc_url) -> None:
        # 使用Chain.configure方法配置区块链。
        # 这里定义了一个区块链类chain_class，并配置了不同区块高度对应的EVM版本。
        # 每个元组代表一个特定的区块高度及其对应的EVM版本。
        chain_class = Chain.configure(
            __name__='Blockchain',
            vm_configuration=(
                (constants.GENESIS_BLOCK_NUMBER, FrontierVMForFuzzTesting),
                (HOMESTEAD_MAINNET_BLOCK, HomesteadVMForFuzzTesting),
                (TANGERINE_WHISTLE_MAINNET_BLOCK, TangerineWhistleVMForFuzzTesting),
                (SPURIOUS_DRAGON_MAINNET_BLOCK, SpuriousDragonVMForFuzzTesting),
                (BYZANTIUM_MAINNET_BLOCK, ByzantiumVMForFuzzTesting),
                (PETERSBURG_MAINNET_BLOCK, PetersburgVMForFuzzTesting),
            ),
        )

        # 定义了一个内部类MyMemoryDB，继承自MemoryDB。
        # 这个类用于模拟区块链的数据库，并提供一个方法rst来重置数据库状态。
        class MyMemoryDB(MemoryDB):
            def __init__(self) -> None:
                self.kv_store = {'storage': dict(), 'account': dict(), 'code': dict()}

            def rst(self) -> None:
                self.kv_store = {'storage': dict(), 'account': dict(), 'code': dict()}

        # 根据提供的IP地址和端口号，以及配置文件中的REMOTE_FUZZING设置，决定是否连接到远程以太坊节点。
        # 如果所有条件满足，则使用Web3库与远程节点建立连接；否则，将self.w3设置为None。
        if eth_rpc_url and settings.REMOTE_FUZZING:
            self.w3 = Web3(HTTPProvider('http://%s' % eth_rpc_url))
        else:
            self.w3 = None
        # 初始化一个日志记录器
        self.logger = initialize_logger("EVM     ")
        # 使用前面定义的chain_class和MyMemoryDB来初始化一个区块链实例self.chain，这个区块链从主网的创世区块头开始。
        self.chain = chain_class.from_genesis_header(AtomicDB(MyMemoryDB()), MAINNET_GENESIS_HEADER)
        self.logger.title(f"Connected to blockchain node at http://{eth_rpc_url}")
        self.logger.info("w3:%s", self.w3)
        # 初始化一个空的账户列表self.accounts，用于存储模拟的账户信息。
        self.accounts = list()
        # 初始化self.snapshot为None，用于存储EVM状态的快照。
        self.snapshot = None
        # 初始化self.vm为None，用于存储当前的虚拟机实例。
        self.vm = None

    # 通过指定的区块标识符来获取区块的详细信息。
    def get_block_by_blockid(self, block_identifier):
        # 验证block_identifier是否是一个有效的256位无符号整数
        validate_uint256(block_identifier)
        # 这个方法将会返回一个包含了区块所有相关信息的对象，如区块号、时间戳、交易列表等。
        return self.w3.eth.getBlock(block_identifier)

    # 这个方法的作用是从本地文件系统中读取之前缓存的区块信息。
    # block_number：要获取的区块号
    def get_cached_block_by_id(self, block_number):
        block = None
        # 使用open函数以二进制读取模式打开一个文件。
        # 文件的路径是当前文件所在目录的路径加上区块号和字符串".block"组成的文件名。
        # 例如，如果区块号是12345，则文件名将是"12345.block"。
        with open(os.path.dirname(os.path.abspath(__file__)) + "/" + ".".join([str(block_number), "block"]), "rb") as f:
            # 使用pickle.load函数从文件中读取数据。
            # pickle是Python的一个模块，它可以序列化和反序列化Python对象结构。
            # 在这里，它被用来从文件中反序列化区块数据。
            block = pickle.load(f)
        return block

    # 属性方法，返回当前虚拟机实例（self.vm）的状态中的账户数据库
    @property
    def storage_emulator(self):
        return self.vm.state._account_db

    # 设置当前的虚拟机（Virtual Machine, VM）实例到指定的区块状态
    # block_identifier：默认值为'latest'。这个参数指定了要设置的区块的标识。
    def set_vm(self, block_identifier='latest'):
        _block = None
        # 检查是否存在一个Web3实例（self.w3），这意味着是否已经与以太坊节点建立了连接。
        if self.w3:
            # 如果block_identifier是'latest'，则获取当前最新的区块号作为区块标识符
            if block_identifier == 'latest':
                block_identifier = self.w3.eth.blockNumber
            # 使用Web3实例获取指定区块标识符的区块信息。
            _block = self.get_block_by_blockid(block_identifier)
        # 如果没有获取到区块信息（_block为None），则尝试从本地缓存中获取。
        self.logger.info("_block:%s", _block)
        if not _block:
            # 如果block_identifier是主网的已知区块（如Homestead、Byzantium、Petersburg），
            # 则尝试从本地缓存中获取这个区块的信息。
            if block_identifier in [HOMESTEAD_MAINNET_BLOCK, BYZANTIUM_MAINNET_BLOCK, PETERSBURG_MAINNET_BLOCK]:
                _block = self.get_cached_block_by_id(block_identifier)
                # self.logger.info("_block:%s", _block)
            else:
                # 如果区块标识符未知或不在预定义的列表中，记录错误并退出程序。
                self.logger.error("Unknown block identifier.")
                sys.exit(-4)
        # 创建一个BlockHeader对象，它包含了从区块中提取的各种信息，如难度、区块号、gas限制、时间戳等。
        block_header = BlockHeader(difficulty=_block.difficulty,
                                   block_number=_block.number,
                                   gas_limit=_block.gasLimit,
                                   timestamp=_block.timestamp,
                                   coinbase=ZERO_ADDRESS,  # default value
                                   parent_hash=_block.parentHash,
                                   uncles_hash=_block.uncles,
                                   state_root=_block.stateRoot,
                                   transaction_root=_block.transactionsRoot,
                                   receipt_root=_block.receiptsRoot,
                                   bloom=0,  # default value
                                   gas_used=_block.gasUsed,
                                   extra_data=_block.extraData,
                                   mix_hash=_block.mixHash,
                                   nonce=_block.nonce)

        # 使用self.chain.get_vm方法和提取的区块头信息来设置当前的虚拟机实例。
        self.vm = self.chain.get_vm(block_header)

    # 执行交易，并可选择是否开启调试模式。
    def execute(self, tx, debug=False):
        if debug:
            logging.getLogger('eth.vm.computation.Computation')
            logging.basicConfig(level=DEBUG2_LEVEL_NUM)
        return self.vm.state.apply_transaction(tx)

    # 重其作用是重置存储模拟器的状态。
    # 这个方法通常用于将模拟的区块链环境恢复到初始状态，以便进行新的测试或模拟。
    def reset(self):
        self.storage_emulator._raw_store_db.wrapped_db.rst()

    # 创建一个虚拟（假）的账户，并设置其属性，如余额、nonce、合约代码和存储。
    def create_fake_account(self, address, nonce=0, balance=settings.ACCOUNT_BALANCE, code='', storage=None):
        # 如果没有提供storage参数，则将其初始化为一个空字典。
        if storage is None:
            storage = {}
        # 将提供的地址转换为规范的地址格式。
        address = to_canonical_address(address)
        # 创建一个新的Account对象，其中包含了指定的nonce和余额。
        account = Account(nonce=nonce, balance=balance)
        # 将新创建的账户添加到虚拟机的状态中。
        self.vm.state._account_db._set_account(address, account)
        # 如果提供了代码（并且代码不为空），则将这段代码设置为给定地址的账户的智能合约代码。
        if code and code != '':
            self.vm.state._account_db.set_code(address, code)
        # 如果提供了存储，则遍历存储中的每个键值对，并将它们添加到账户的存储中。
        # 这里使用了decode_hex函数将十六进制的键和值转换为字节。
        if storage:
            for k, v in storage.items():
                self.vm.state._account_db.set_storage(address, int.from_bytes(decode_hex(k), byteorder="big"),
                                                      int.from_bytes(decode_hex(v), byteorder="big"))
        # 记录一条调试信息，说明已创建了一个新账户，包括账户的地址和余额。
        self.logger.info("Created account %s with balance %s", encode_hex(address), account.balance)
        return encode_hex(address)

    # 检查给定地址的账户是否存在于当前虚拟机（EVM）状态的账户数据库中
    def has_account(self, address):
        address = to_canonical_address(address)
        return self.vm.state._account_db._has_account(address)

    # 创建并执行一个部署合约的交易，然后返回交易的执行结果。
    # 模拟环境中部署智能合约的核心功能
    # creator:合约创建者的地址
    # bin_code: 合约的二进制代码
    # amount:发送到合约的以太币数量，默认为0
    # gas:（交易的gas限制，默认从设置中获取）
    # gas_price:（gas价格，默认从设置中获取）
    # debug:（是否开启调试模式，默认为False）
    def deploy_contract(self, creator, bin_code, amount=0, gas=settings.GAS_LIMIT, gas_price=settings.GAS_PRICE,
                        debug=False):
        # 获取创建者账户的nonce值。Nonce是一个用于防止交易重放的计数器，表示账户已发起的交易数量。
        nonce = self.vm.state.get_nonce(decode_hex(creator))
        # 创建一个未签名的交易。这个交易包括nonce、gas价格、gas限制、接收地址（创建合约的特殊地址）、
        # 发送的以太币数量和合约代码。
        # CREATE_CONTRACT_ADDRESS是一个用于表示合约创建的特殊地址。
        tx = self.vm.create_unsigned_transaction(
            nonce=nonce,
            gas_price=gas_price,
            gas=gas,
            to=CREATE_CONTRACT_ADDRESS,
            value=amount,
            data=decode_hex(bin_code),
        )

        # 使用SpoofTransaction对交易进行包装，指定交易的发送者。
        # 这允许在不实际签名交易的情况下模拟交易的发送。
        tx = SpoofTransaction(tx, from_=decode_hex(creator))
        # 执行交易，并根据debug参数决定是否开启调试模式。
        # execute方法将应用交易到当前的虚拟机状态，并返回执行结果。
        result = self.execute(tx, debug=debug)
        # 获取新创建的合约的地址。合约地址是从交易执行结果中提取的。
        address = to_canonical_address(encode_hex(result.msg.storage_address))
        self.logger.info("tx_address:%s", address)
        # 在存储模拟器中为新创建的合约设置余额。
        # 这里设定余额为1，这是为了确保合约在测试中有足够的余额来执行操作。
        self.storage_emulator.set_balance(address, 1)
        return result

    # 部署（执行）交易
    # input：交易数据
    # gas_price
    def deploy_transaction(self, input, gas_price=settings.GAS_PRICE, debug=False):
        # 从输入参数中提取交易信息
        transaction = input["transaction"]
        # 将交易发起者地址（"from"）从十六进制字符串转换为字节
        from_account = decode_hex(transaction["from"])
        # 获取发起者账户的nonce值。
        nonce = self.vm.state.get_nonce(from_account)
        # 尝试将交易接收者地址（"to"）从十六进制字符串转换为字节
        try:
            to = decode_hex(transaction["to"])
        except:
            to = transaction["to"]
        # 使用虚拟机的create_unsigned_transaction方法创建一个未签名的交易。
        tx = self.vm.create_unsigned_transaction(
            nonce=nonce,
            gas_price=gas_price,
            gas=transaction["gaslimit"],
            to=to,
            value=transaction["value"],
            data=decode_hex(transaction["data"]),
        )
        # 使用SpoofTransaction包装交易，指定交易的发起者。
        # 这允许在不实际签名的情况下模拟交易的发起。
        tx = SpoofTransaction(tx, from_=from_account)

        # 根据输入参数中的block、global_state和environment信息，调整虚拟机状态。
        block = input["block"]
        if "timestamp" in block and block["timestamp"] is not None:
            # 设置时间戳
            self.vm.state.fuzzed_timestamp = block["timestamp"]
        else:
            self.vm.state.fuzzed_timestamp = None
        if "blocknumber" in block and block["blocknumber"] is not None:
            # 设置区块号
            self.vm.state.fuzzed_blocknumber = block["blocknumber"]
        else:
            self.vm.state.fuzzed_blocknumber = None

        # 获取全局状态
        global_state = input["global_state"]
        if "balance" in global_state and global_state["balance"] is not None:
            # 设置账户余额
            self.vm.state.fuzzed_balance = global_state["balance"]
        else:
            self.vm.state.fuzzed_balance = None

        if "call_return" in global_state and global_state["call_return"] is not None \
                and len(global_state["call_return"]) > 0:
            # 设置调用返回值
            self.vm.state.fuzzed_call_return = global_state["call_return"]

        if "extcodesize" in global_state and global_state["extcodesize"] is not None \
                and len(global_state["extcodesize"]) > 0:
            # 设置执行字节码大小
            self.vm.state.fuzzed_extcodesize = global_state["extcodesize"]

        # 从输入加载环境
        environment = input["environment"]
        if "returndatasize" in environment and environment["returndatasize"] is not None:
            # 设置返回值大小
            self.vm.state.fuzzed_returndatasize = environment["returndatasize"]

        # 在存储模拟器中为交易发起者账户设置余额。
        self.storage_emulator.set_balance(from_account, settings.ACCOUNT_BALANCE)
        # 执行交易，并根据debug参数决定是否开启调试模式。
        # execute方法应用交易到当前的虚拟机状态，并返回执行结果。
        return self.execute(tx, debug=debug)

    # 获取余额
    def get_balance(self, address):
        return self.storage_emulator.get_balance(address)

    # 获取指定地址合约代码
    def get_code(self, address):
        return self.storage_emulator.get_code(address)

    # 设置代码
    def set_code(self, address, code):
        return self.storage_emulator.set_code(address, code)

    # 创建快照
    def create_snapshot(self):
        self.snapshot = self.storage_emulator.record()
        self.storage_emulator.set_snapshot(self.snapshot)

    # 从快照恢复
    def restore_from_snapshot(self):
        self.storage_emulator.discard(self.snapshot)

    # 获取账户列表
    def get_accounts(self):
        return [encode_hex(x) for x in self.storage_emulator._raw_store_db.wrapped_db["account"].keys()]

    # 根据名称设置虚拟机
    def set_vm_by_name(self, EVM_VERSION):
        if EVM_VERSION == "homestead":
            self.set_vm(HOMESTEAD_MAINNET_BLOCK)
        elif EVM_VERSION == "byzantium":
            self.set_vm(BYZANTIUM_MAINNET_BLOCK)
        elif EVM_VERSION == "petersburg":
            self.set_vm(PETERSBURG_MAINNET_BLOCK)
        else:
            raise Exception("Unknown EVM version, please choose either 'homestead', 'byzantium' or 'petersburg'.")

    # 创建一组虚假账户，用于测试
    def create_fake_accounts(self):
        self.accounts.append(self.create_fake_account("0xcafebabecafebabecafebabecafebabecafebabe"))
        for address in settings.ATTACKER_ACCOUNTS:
            self.accounts.append(self.create_fake_account(address))
