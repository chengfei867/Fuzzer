#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess

from .utils import remove_swarm_hash, convert_stack_value_to_int, initialize_logger


# 代表控制流图中的一个单独的执行块，其中的指令从入口到出口是直线执行的，没有分支。
# 这个类的每个实例代表了字节码中的一个这样的块。
class BasicBlock:
    def __init__(self):
        # 起始地址
        self.start_address    = None
        # 结束地址
        self.end_address      = None
        # 一个字典，键是指令的地址，值是相应的指令
        self.instructions     = {}

    def __str__(self):
        string  = "---------Basic Block---------\n"
        string += "Start address: %d (0x%x)\n" % ((self.start_address, self.start_address) if self.start_address else (0, 0))
        string += "End address: %d (0x%x)\n" % ((self.end_address, self.end_address) if self.end_address else (0, 0))
        string += "Instructions: "+str(self.instructions)+"\n"
        string += "-----------------------------"
        return string

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, _other):
        return self.__dict__ == _other.__dict__

    # 设置起始地址
    def set_start_address(self, start_address):
        self.start_address = start_address

    # 获取起始地址
    def get_start_address(self):
        return self.start_address

    # 设置终止地址
    def set_end_address(self, end_address):
        self.end_address = end_address

    # 得到终止地址
    def get_end_address(self):
        return self.end_address

    # 添加一条指令
    def add_instruction(self, key, value):
        self.instructions[key] = value

    # 返回基本块中所有指令的字典
    def get_instructions(self):
        return self.instructions

class ControlFlowGraph:
    def __init__(self):
        global logger
        # 存储边
        self.edges = {}
        # 存储顶点
        self.vertices = {}
        # 记录已访问过的程序计数器
        self.visited_pcs = set()
        # 记录已访问过的分支
        self.visited_branches = {}
        # 记录产生错误的PC位置
        self.error_pcs = set()
        # 指示程序是否有可能发送以太币（Ether）
        self.can_send_ether = False
        # 初始化一个日志记录器
        logger = initialize_logger("CFG   ")

    def build(self, bytecode, evm_version):
        # 这行代码首先处理传入的字节码字符串。
        # 它移除Swarm哈希（如果存在），去掉字节码字符串前的"0x"，然后将其转换成字节对象。
        # Swarm哈希是Solidity编译器附加的元数据，通常不是字节码执行的一部分。
        bytecode = bytes.fromhex(remove_swarm_hash(bytecode).replace("0x", ""))
        # （程序计数器）初始化为0，这将是我们遍历字节码时的索引。
        current_pc = 0
        # 前一个操作码的pc
        previous_pc = 0
        # 存储当前正在构建的基本块对象
        basic_block = None
        # 上一个操作码
        previous_opcode = None
        # push操作的值
        previous_push_value = None
        # 开始循环遍历字节码中的每个字节
        while current_pc < len(bytecode):
            # 从字节码中取出当前操作码
            opcode = bytecode[current_pc]

            # 如果当前操作码是会创建合约或者发送以太的操作（比如CALL或SELFDESTRUCT），
            # can_send_ether标记为True。
            if opcode in self.opcode_to_mnemonic[evm_version] and self.opcode_to_mnemonic[evm_version][opcode] in ["CREATE", "CALL", "DELEGATECALL", "SELFDESTRUCT", "SUICIDE"]:
                self.can_send_ether = True

            # 如果前一个操作码是SELFDESTRUCT，这意味着合约将自毁，
            # 当前基本块结束，需要保存并重置basic_block。
            if previous_opcode == 255: # SELFDESTRUCT
                basic_block.set_end_address(previous_pc)
                # 保存
                self.vertices[current_pc] = basic_block
                basic_block = None

            # 如果basic_block是None，这意味着我们需要开始一个新的基本块。
            if basic_block is None:
                basic_block = BasicBlock()
                basic_block.set_start_address(current_pc)

            # 检查当前的操作码是否是JUMPDEST（操作码为91）。
            # 如果是，并且当前基本块中已经有指令（即它不为空）
            if opcode == 91 and basic_block.get_instructions(): # JUMPDEST
                # 将前一个PC值设置为当前基本块的结束地址，因为JUMPDEST意味着一个新基本块的开始
                basic_block.set_end_address(previous_pc)
                # 检查前一个PC是否不在边列表中，且前一个操作码不是终止性或条件性指令
                if previous_pc not in self.edges and previous_opcode not in [0, 86, 87, 243, 253, 254, 255]: # Terminating/Conditional: STOP, JUMP, JUMPI, RETURN, REVERT, INVALID, SELFDESTRUCT
                    # 初始化一个新列表，并将当前PC（JUMPDEST指令的位置）添加到这个列表中。
                    self.edges[previous_pc] = []
                    self.edges[previous_pc].append(current_pc)
                # 将当前基本块（结束于JUMPDEST之前的指令）添加到顶点列表中，键是基本块的起始地址。
                self.vertices[current_pc] = basic_block
                # 新建一个基本块
                basic_block = BasicBlock()
                # 该基本块的起始地址为当前pc
                basic_block.set_start_address(current_pc)

            # 处理非push指令
            if opcode < 96 or opcode > 127: # PUSH??
                # 如果当前的操作码是一个已知的操作码（即它存在于opcode_to_mnemonic字典中）
                if opcode in self.opcode_to_mnemonic[evm_version]:
                    # 添加到当前块指令集中
                    basic_block.add_instruction(current_pc, self.opcode_to_mnemonic[evm_version][opcode])
                else:
                    # 否则添加一个Missing操作码，表示无效或位置操作码
                    basic_block.add_instruction(current_pc, "Missing opcode "+hex(opcode))

            # 处理jump和jumpi操作码
            if opcode == 86 or opcode == 87: # JUMP or JUMPI
                # 若当前的操作码是jump或者jumpi表示即将进行跳转，
                # 当前基本块结束
                basic_block.set_end_address(current_pc)
                # 将当前基本块添加到cfg的顶点集合中
                self.vertices[current_pc] = basic_block
                # 重置基本块，表示新的顶点
                basic_block = None
                # 若当前操作码为jump，并且前一个操作码为push类型
                if opcode == 86 and previous_opcode and previous_opcode >= 96 and previous_opcode <= 127:
                    # 将之前的PUSH操作提供的值作为跳转目标添加到当前PC的边列表中
                    if current_pc not in self.edges:
                        self.edges[current_pc] = []
                    self.edges[current_pc].append(previous_push_value)
                # 如果是jumpi(条件跳转)
                if opcode == 87:
                    # 同样先判断有无以当前边为起始地址的目标地址集合
                    if current_pc not in self.edges:
                        self.edges[current_pc] = []
                    # 首先将当前指令的下一条指令添加到边目标地址集合中，
                    # 因为jumpi可能不跳转，而是继续执行下一条指令
                    self.edges[current_pc].append(current_pc+1)
                    # 也有可能跳转，将之前push的值添加到当前边的目标地址集合中
                    if previous_opcode and previous_opcode >= 96 and previous_opcode <= 127:
                        if current_pc not in self.edges:
                            self.edges[current_pc] = []
                        self.edges[current_pc].append(previous_push_value)

            # 如果当前操作码不是上述的任何一种，则表示在同一个基本块中的操作，
            # 先将当前地址赋值给前一个地址
            previous_pc = current_pc
            # 如果是push指令
            if opcode >= 96 and opcode <= 127: # PUSH??
                # 计算PUSH操作将要推入栈中的字节数。例如，PUSH1的操作码是96，意味着它推入1个字节的数据。
                size = opcode - 96 + 1
                # 这个循环构建PUSH操作的数据值。它遍历随PUSH操作码紧跟的字节，
                # 并将这些字节累加到previous_push_value字符串中。
                previous_push_value = ""
                for i in range(size):
                    try:
                        # bytecode[current_pc+i+1]：获取当前PUSH操作码后的第i个字节。
                        #                           由于PUSH操作码本身占用了一个字节，
                        #                           所以要加1来获取紧随其后的数据字节。
                        # hex(bytecode[current_pc+i+1]): 将获取到的字节转换为十六进制字符串。
                        # .replace("0x", ""): 移除十六进制字符串中的"0x"前缀。
                        # .zfill(2): 确保字符串长度为2。如果转换后的十六进制数不足两位（例如，"a"），
                        #            这个函数会在前面填充0，使其变为"0a"。这是因为每个字节应该表示为两位十六进制数。
                        previous_push_value += str(hex(bytecode[current_pc+i+1])).replace("0x", "").zfill(2)
                    except Exception as e:
                        pass
                # 如果成功获取到PUSH操作的值
                if previous_push_value:
                    # 前一步我们将多有的数字字节去除”0x“后凭拼接起来，这一步在总的数据字节前面加上0x
                    previous_push_value = "0x" + previous_push_value
                    # 将当前push指令及其数据添加到当前块指令集
                    # key：current_pc
                    # value：push指令+数据
                    basic_block.add_instruction(current_pc, self.opcode_to_mnemonic[evm_version][opcode]+" "+previous_push_value)
                    # 然后，将previous_push_value（目前为十六进制字符串格式）转换成整数。
                    previous_push_value = int(previous_push_value, 16)
                    # 更新当前指针
                    current_pc += size
            # 迭代
            current_pc += 1
            previous_opcode = opcode
        # 当字节码遍历完毕
        if basic_block:
            # 将最后一个基本块的结束地址设置为previous_pc
            basic_block.set_end_address(previous_pc)
            # 将当前块加入顶点集合，key为当前current_pc表示的是该基本块到这里就结束了
            self.vertices[current_pc] = basic_block

    def execute(self, pc, stack, mnemonic, visited_branches, error_pcs):
        if mnemonic == "JUMP":
            if pc not in self.edges:
                self.edges[pc] = []
            if convert_stack_value_to_int(stack[-1]) not in self.edges[pc]:
                self.edges[pc].append(convert_stack_value_to_int(stack[-1]))
        self.visited_pcs.add(pc)
        self.visited_branches = visited_branches
        self.error_pcs = error_pcs

    # 保存cfg图
    def save_control_flow_graph(self, filename, extension):
        f = open(filename+'.dot', 'w')
        f.write('digraph confuzzius_cfg {\n')
        f.write('rankdir = TB;\n')
        f.write('size = "240"\n')
        f.write('graph[fontname = Courier, fontsize = 14.0, labeljust = l, nojustify = true];node[shape = record];\n')
        address_width = 10
        for basic_block in self.vertices.values():
            if len(hex(list(basic_block.get_instructions().keys())[-1])) > address_width:
                address_width = len(hex(list(basic_block.get_instructions().keys())[-1]))
        for basic_block in self.vertices.values():
            # Draw vertices
            label = '"'+hex(basic_block.get_start_address())+'"[label="'
            for address in basic_block.get_instructions():
                label += "{0:#0{1}x}".format(address, address_width)+" "+basic_block.get_instructions()[address]+"\l"
            visited_basic_block = False
            for pc in self.error_pcs:
                if pc in basic_block.get_instructions().keys():
                    f.write(label+'",style=filled,fillcolor=red];\n')
                    visited_basic_block = True
                    break
            if not visited_basic_block:
                if  basic_block.get_start_address() in self.visited_pcs and basic_block.get_end_address() in self.visited_pcs:
                    f.write(label+'",style=filled,fillcolor=gray];\n')
                else:
                    f.write(label+'",style=filled,fillcolor=white];\n')
            # Draw edges
            if basic_block.get_end_address() in self.edges:
                # JUMPI
                if list(basic_block.get_instructions().values())[-1] == "JUMPI":
                    if hex(basic_block.get_end_address()) in self.visited_branches and 0 in self.visited_branches[hex(basic_block.get_end_address())] and self.visited_branches[hex(basic_block.get_end_address())][0]["expression"]:
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][0])+'" [label=" '+str(self.visited_branches[hex(basic_block.get_end_address())][0]["expression"][-1])+'",color="red"];\n')
                    else:
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][0])+'" [label="",color="red"];\n')
                    if hex(basic_block.get_end_address()) in self.visited_branches and 1 in self.visited_branches[hex(basic_block.get_end_address())] and self.visited_branches[hex(basic_block.get_end_address())][1]["expression"]:
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][1])+'" [label=" '+str(self.visited_branches[hex(basic_block.get_end_address())][1]["expression"][-1])+'",color="green"];\n')
                    else:
                        end_address = basic_block.get_end_address()
                        if end_address in self.edges and len(self.edges[end_address]) > 1:
                            f.write('"' + hex(basic_block.get_start_address()) + '" -> "' + hex(
                                self.edges[end_address][1]) + '" [label="",color="green"];\n')
                # Other instructions
                else:
                    for i in range(len(self.edges[basic_block.get_end_address()])):
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][i])+'" [label="",color="black"];\n')
        f.write('}\n')
        f.close()
        if not subprocess.call('dot '+filename+'.dot -T'+extension+' -o '+filename+'.'+extension, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
            print("Graphviz is not available. Please install Graphviz from https://www.graphviz.org/download/.")
        else:
            os.remove(filename+".dot")

    # 不同版本的操作码集合
    opcode_to_mnemonic = {
        'homestead': {
            # 0s: Stop and Arithmetic Operations
              0: 'STOP',
              1: 'ADD',
              2: 'MUL',
              3: 'SUB',
              4: 'DIV',
              5: 'SDIV',
              6: 'MOD',
              7: 'SMOD',
              8: 'ADDMOD',
              9: 'MULMOD',
             10: 'EXP',
             11: 'SIGNEXTEND',
            # 10s: Comparison & Bitwise Logic Operations
             16: 'LT',
             17: 'GT',
             18: 'SLT',
             19: 'SGT',
             20: 'EQ',
             21: 'ISZERO',
             22: 'AND',
             23: 'OR',
             24: 'XOR',
             25: 'NOT',
             26: 'BYTE',
            # 20s: SHA3
             32: 'SHA3',
            # 30s: Environmental Information
             48: 'ADDRESS',
             49: 'BALANCE',
             50: 'ORIGIN',
             51: 'CALLER',
             52: 'CALLVALUE',
             53: 'CALLDATALOAD',
             54: 'CALLDATASIZE',
             55: 'CALLDATACOPY',
             56: 'CODESIZE',
             57: 'CODECOPY',
             58: 'GASPRICE',
             59: 'EXTCODESIZE',
             60: 'EXTCODECOPY',
            # 40s: Block Information
             64: 'BLOCKHASH',
             65: 'COINBASE',
             66: 'TIMESTAMP',
             67: 'NUMBER',
             68: 'DIFFICULTY',
             69: 'GASLIMIT',
            # 50s: Stack, Memory, Storage and Flow Operations
             80: 'POP',
             81: 'MLOAD',
             82: 'MSTORE',
             83: 'MSTORE8',
             84: 'SLOAD',
             85: 'SSTORE',
             86: 'JUMP',
             87: 'JUMPI',
             88: 'PC',
             89: 'MSIZE',
             90: 'GAS',
             91: 'JUMPDEST',
            # 60s & 70s: Push Operations
             96: 'PUSH1',
             97: 'PUSH2',
             98: 'PUSH3',
             99: 'PUSH4',
            100: 'PUSH5',
            101: 'PUSH6',
            102: 'PUSH7',
            103: 'PUSH8',
            104: 'PUSH9',
            105: 'PUSH10',
            106: 'PUSH11',
            107: 'PUSH12',
            108: 'PUSH13',
            109: 'PUSH14',
            110: 'PUSH15',
            111: 'PUSH16',
            112: 'PUSH17',
            113: 'PUSH18',
            114: 'PUSH19',
            115: 'PUSH20',
            116: 'PUSH21',
            117: 'PUSH22',
            118: 'PUSH23',
            119: 'PUSH24',
            120: 'PUSH25',
            121: 'PUSH26',
            122: 'PUSH27',
            123: 'PUSH28',
            124: 'PUSH29',
            125: 'PUSH30',
            126: 'PUSH31',
            127: 'PUSH32',
            # 80s: Duplication Operations
            128: 'DUP1',
            129: 'DUP2',
            130: 'DUP3',
            131: 'DUP4',
            132: 'DUP5',
            133: 'DUP6',
            134: 'DUP7',
            135: 'DUP8',
            136: 'DUP9',
            137: 'DUP10',
            138: 'DUP11',
            139: 'DUP12',
            140: 'DUP13',
            141: 'DUP14',
            142: 'DUP15',
            143: 'DUP16',
            # 90s: Exchange Operations
            144: 'SWAP1',
            145: 'SWAP2',
            146: 'SWAP3',
            147: 'SWAP4',
            148: 'SWAP5',
            149: 'SWAP6',
            150: 'SWAP7',
            151: 'SWAP8',
            152: 'SWAP9',
            153: 'SWAP10',
            154: 'SWAP11',
            155: 'SWAP12',
            156: 'SWAP13',
            157: 'SWAP14',
            158: 'SWAP15',
            159: 'SWAP16',
            # a0s: Logging Operations
            160: 'LOG0',
            161: 'LOG1',
            162: 'LOG2',
            163: 'LOG3',
            164: 'LOG4',
            # f0s: System Operations
            240: 'CREATE',
            241: 'CALL',
            242: 'CALLCODE',
            243: 'RETURN',
            244: 'DELEGATECALL',
            254: 'ASSERTFAIL',
            255: 'SUICIDE'
        },
        'byzantium': {
            # 0s: Stop and Arithmetic Operations
              0: 'STOP',
              1: 'ADD',
              2: 'MUL',
              3: 'SUB',
              4: 'DIV',
              5: 'SDIV',
              6: 'MOD',
              7: 'SMOD',
              8: 'ADDMOD',
              9: 'MULMOD',
             10: 'EXP',
             11: 'SIGNEXTEND',
            # 10s: Comparison & Bitwise Logic Operations
             16: 'LT',
             17: 'GT',
             18: 'SLT',
             19: 'SGT',
             20: 'EQ',
             21: 'ISZERO',
             22: 'AND',
             23: 'OR',
             24: 'XOR',
             25: 'NOT',
             26: 'BYTE',
            # 20s: SHA3
             32: 'SHA3',
            # 30s: Environmental Information
             48: 'ADDRESS',
             49: 'BALANCE',
             50: 'ORIGIN',
             51: 'CALLER',
             52: 'CALLVALUE',
             53: 'CALLDATALOAD',
             54: 'CALLDATASIZE',
             55: 'CALLDATACOPY',
             56: 'CODESIZE',
             57: 'CODECOPY',
             58: 'GASPRICE',
             59: 'EXTCODESIZE',
             60: 'EXTCODECOPY',
             61: 'RETURNDATASIZE',
             62: 'RETURNDATACOPY',
            # 40s: Block Information
             64: 'BLOCKHASH',
             65: 'COINBASE',
             66: 'TIMESTAMP',
             67: 'NUMBER',
             68: 'DIFFICULTY',
             69: 'GASLIMIT',
            # 50s: Stack, Memory, Storage and Flow Operations
             80: 'POP',
             81: 'MLOAD',
             82: 'MSTORE',
             83: 'MSTORE8',
             84: 'SLOAD',
             85: 'SSTORE',
             86: 'JUMP',
             87: 'JUMPI',
             88: 'PC',
             89: 'MSIZE',
             90: 'GAS',
             91: 'JUMPDEST',
            # 60s & 70s: Push Operations
             96: 'PUSH1',
             97: 'PUSH2',
             98: 'PUSH3',
             99: 'PUSH4',
            100: 'PUSH5',
            101: 'PUSH6',
            102: 'PUSH7',
            103: 'PUSH8',
            104: 'PUSH9',
            105: 'PUSH10',
            106: 'PUSH11',
            107: 'PUSH12',
            108: 'PUSH13',
            109: 'PUSH14',
            110: 'PUSH15',
            111: 'PUSH16',
            112: 'PUSH17',
            113: 'PUSH18',
            114: 'PUSH19',
            115: 'PUSH20',
            116: 'PUSH21',
            117: 'PUSH22',
            118: 'PUSH23',
            119: 'PUSH24',
            120: 'PUSH25',
            121: 'PUSH26',
            122: 'PUSH27',
            123: 'PUSH28',
            124: 'PUSH29',
            125: 'PUSH30',
            126: 'PUSH31',
            127: 'PUSH32',
            # 80s: Duplication Operations
            128: 'DUP1',
            129: 'DUP2',
            130: 'DUP3',
            131: 'DUP4',
            132: 'DUP5',
            133: 'DUP6',
            134: 'DUP7',
            135: 'DUP8',
            136: 'DUP9',
            137: 'DUP10',
            138: 'DUP11',
            139: 'DUP12',
            140: 'DUP13',
            141: 'DUP14',
            142: 'DUP15',
            143: 'DUP16',
            # 90s: Exchange Operations
            144: 'SWAP1',
            145: 'SWAP2',
            146: 'SWAP3',
            147: 'SWAP4',
            148: 'SWAP5',
            149: 'SWAP6',
            150: 'SWAP7',
            151: 'SWAP8',
            152: 'SWAP9',
            153: 'SWAP10',
            154: 'SWAP11',
            155: 'SWAP12',
            156: 'SWAP13',
            157: 'SWAP14',
            158: 'SWAP15',
            159: 'SWAP16',
            # a0s: Logging Operations
            160: 'LOG0',
            161: 'LOG1',
            162: 'LOG2',
            163: 'LOG3',
            164: 'LOG4',
            # f0s: System Operations
            240: 'CREATE',
            241: 'CALL',
            242: 'CALLCODE',
            243: 'RETURN',
            244: 'DELEGATECALL',
            250: 'STATICCALL',
            253: 'REVERT',
            254: 'INVALID',
            255: 'SELFDESTRUCT'
        },
        'petersburg': {
            # 0s: Stop and Arithmetic Operations
              0: 'STOP',
              1: 'ADD',
              2: 'MUL',
              3: 'SUB',
              4: 'DIV',
              5: 'SDIV',
              6: 'MOD',
              7: 'SMOD',
              8: 'ADDMOD',
              9: 'MULMOD',
             10: 'EXP',
             11: 'SIGNEXTEND',
            # 10s: Comparison & Bitwise Logic Operations
             16: 'LT',
             17: 'GT',
             18: 'SLT',
             19: 'SGT',
             20: 'EQ',
             21: 'ISZERO',
             22: 'AND',
             23: 'OR',
             24: 'XOR',
             25: 'NOT',
             26: 'BYTE',
             27: 'SHL',
             28: 'SHR',
             29: 'SAR',
            # 20s: SHA3
             32: 'SHA3',
            # 30s: Environmental Information
             48: 'ADDRESS',
             49: 'BALANCE',
             50: 'ORIGIN',
             51: 'CALLER',
             52: 'CALLVALUE',
             53: 'CALLDATALOAD',
             54: 'CALLDATASIZE',
             55: 'CALLDATACOPY',
             56: 'CODESIZE',
             57: 'CODECOPY',
             58: 'GASPRICE',
             59: 'EXTCODESIZE',
             60: 'EXTCODECOPY',
             61: 'RETURNDATASIZE',
             62: 'RETURNDATACOPY',
             63: 'EXTCODEHASH',
            # 40s: Block Information
             64: 'BLOCKHASH',
             65: 'COINBASE',
             66: 'TIMESTAMP',
             67: 'NUMBER',
             68: 'DIFFICULTY',
             69: 'GASLIMIT',
             70: 'CHAINID',
             71: 'SELFBALANCE',
            # 50s: Stack, Memory, Storage and Flow Operations
             80: 'POP',
             81: 'MLOAD',
             82: 'MSTORE',
             83: 'MSTORE8',
             84: 'SLOAD',
             85: 'SSTORE',
             86: 'JUMP',
             87: 'JUMPI',
             88: 'PC',
             89: 'MSIZE',
             90: 'GAS',
             91: 'JUMPDEST',
            # 60s & 70s: Push Operations
             96: 'PUSH1',
             97: 'PUSH2',
             98: 'PUSH3',
             99: 'PUSH4',
            100: 'PUSH5',
            101: 'PUSH6',
            102: 'PUSH7',
            103: 'PUSH8',
            104: 'PUSH9',
            105: 'PUSH10',
            106: 'PUSH11',
            107: 'PUSH12',
            108: 'PUSH13',
            109: 'PUSH14',
            110: 'PUSH15',
            111: 'PUSH16',
            112: 'PUSH17',
            113: 'PUSH18',
            114: 'PUSH19',
            115: 'PUSH20',
            116: 'PUSH21',
            117: 'PUSH22',
            118: 'PUSH23',
            119: 'PUSH24',
            120: 'PUSH25',
            121: 'PUSH26',
            122: 'PUSH27',
            123: 'PUSH28',
            124: 'PUSH29',
            125: 'PUSH30',
            126: 'PUSH31',
            127: 'PUSH32',
            # 80s: Duplication Operations
            128: 'DUP1',
            129: 'DUP2',
            130: 'DUP3',
            131: 'DUP4',
            132: 'DUP5',
            133: 'DUP6',
            134: 'DUP7',
            135: 'DUP8',
            136: 'DUP9',
            137: 'DUP10',
            138: 'DUP11',
            139: 'DUP12',
            140: 'DUP13',
            141: 'DUP14',
            142: 'DUP15',
            143: 'DUP16',
            # 90s: Exchange Operations
            144: 'SWAP1',
            145: 'SWAP2',
            146: 'SWAP3',
            147: 'SWAP4',
            148: 'SWAP5',
            149: 'SWAP6',
            150: 'SWAP7',
            151: 'SWAP8',
            152: 'SWAP9',
            153: 'SWAP10',
            154: 'SWAP11',
            155: 'SWAP12',
            156: 'SWAP13',
            157: 'SWAP14',
            158: 'SWAP15',
            159: 'SWAP16',
            # a0s: Logging Operations
            160: 'LOG0',
            161: 'LOG1',
            162: 'LOG2',
            163: 'LOG3',
            164: 'LOG4',
            # f0s: System Operations
            240: 'CREATE',
            241: 'CALL',
            242: 'CALLCODE',
            243: 'RETURN',
            244: 'DELEGATECALL',
            245: 'CREATE2',
            250: 'STATICCALL',
            253: 'REVERT',
            254: 'INVALID',
            255: 'SELFDESTRUCT'
        }
    }
