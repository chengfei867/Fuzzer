#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils.utils import get_pcs_and_jumpis

# 管理源代码文件
class Source:
    def __init__(self, filename):
        self.filename = filename
        self.content = self._load_content()
        self.line_break_positions = self._load_line_break_positions()

    # 读取由 filename 指定的文件的全部内容并存储。
    def _load_content(self):
        with open(self.filename, 'r') as f:
            content = f.read()
        return content

    # 存储内容中换行符（\n）的位置，这对于定位特定行非常有用。
    def _load_line_break_positions(self):
        return [i for i, letter in enumerate(self.content) if letter == '\n']

# 处理编译器输出中字节码与其对应源代码之间的映射。
class SourceMap:
    # 存储 Solidity 编译器输出的映射信息
    position_groups = {}
    # 源文件实例
    sources = {}
    # 编译器输出
    compiler_output = None

    # cname格式： solidity源文件名称：待测合约名称
    # compiler_output：这是从 Solidity 编译器（或类似的编译工具）得到的输出数据，
    # 通常包含编译后的字节码、抽象语法树（AST）、源代码映射等信息。
    def __init__(self, cname, compiler_output):
        self.cname = cname
        SourceMap.compiler_output = compiler_output
        # 加载源码映射信息，源码映射信息用于将编译后的字节码映射回原始源代码。
        SourceMap.position_groups = SourceMap._load_position_groups_standard_json()
        # 获取Source对象，该对象包含了智能合约的源代码
        self.source = self._get_source()
        # 提取智能合约中每个指令的源码位置信息
        self.positions = self._get_positions()
        # 获取一组包含程序计数器（PC）与源码位置对应关系的数据，这个方法将编译后的字节码中的每个指令映射到源代码中的具体位置。
        self.instr_positions = self._get_instr_positions()

    def get_source_code(self, pc):
        try:
            pos = self.instr_positions[pc]
        except:
            return ""
        begin = pos['begin']
        end = pos['end']
        return self.source.content[begin:end]

    def get_buggy_line(self, pc):
        #print(self.instr_positions)
        try:
            pos = self.instr_positions[pc]
        except:
            return ""
        #location = self.get_location(pc)
        #print(location)
        try:
            #begin = self.source.line_break_positions[location['begin']['line'] - 1] + 1
            begin = pos['begin']
            end = pos['end']
            #print(begin)
            #print(end)
            #print(self.source.content[begin:end])
            return self.source.content[begin:end]
        except:
            return ""

    def get_location(self, pc):
        pos = self.instr_positions[pc]
        return self._convert_offset_to_line_column(pos)

    def _get_source(self):
        fname = self.get_filename()
        if fname not in SourceMap.sources:
            SourceMap.sources[fname] = Source(fname)
        return SourceMap.sources[fname]

    # 返回编译器输出中的"contracts"部分
    @classmethod
    def _load_position_groups_standard_json(cls):
        return cls.compiler_output["contracts"]

    def _get_positions(self):
        filename, contract_name = self.cname.split(":")
        asm = SourceMap.position_groups[filename][contract_name]['evm']['legacyAssembly']['.data']['0']
        positions = asm['.code']
        while(True):
            try:
                positions.append(None)
                positions += asm['.data']['0']['.code']
                asm = asm['.data']['0']
            except:
                break
        return positions

    def _get_instr_positions(self):
        j = 0
        instr_positions = {}
        try:
            filename, contract_name = self.cname.split(":")
            bytecode = self.compiler_output['contracts'][filename][contract_name]["evm"]["deployedBytecode"]["object"]
            pcs = get_pcs_and_jumpis(bytecode)[0]
            for i in range(len(self.positions)):
                if self.positions[i] and self.positions[i]['name'] != 'tag':
                    instr_positions[pcs[j]] = self.positions[i]
                    j += 1
            return instr_positions
        except:
            return instr_positions

    def _convert_offset_to_line_column(self, pos):
        ret = {}
        ret['begin'] = None
        ret['end'] = None
        if pos['begin'] >= 0 and (pos['end'] - pos['begin'] + 1) >= 0:
            ret['begin'] = self._convert_from_char_pos(pos['begin'])
            ret['end'] = self._convert_from_char_pos(pos['end'])
        return ret

    def _convert_from_char_pos(self, pos):
        line = self._find_lower_bound(pos, self.source.line_break_positions)
        col = 0
        if line in self.source.line_break_positions:
            if self.source.line_break_positions[line] != pos:
                line += 1
            begin_col = 0 if line == 0 else self.source.line_break_positions[line - 1] + 1
            col = pos - begin_col
        else:
            line += 1
        return {'line': line, 'column': col}

    def _find_lower_bound(self, target, array):
        start = 0
        length = len(array)
        while length > 0:
            half = length >> 1
            middle = start + half
            if array[middle] <= target:
                length = length - 1 - half
                start = middle + 1
            else:
                length = half
        return start - 1

    def get_filename(self):
        return self.cname.split(":")[0]
