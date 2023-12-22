#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import solcx
import random
import argparse

from eth_utils import encode_hex, to_canonical_address
from z3 import Solver

from evm import InstrumentedEVM
from detectors import DetectorExecutor
from engine import EvolutionaryFuzzingEngine
from engine.components import Generator, Individual, Population
from engine.analysis import SymbolicTaintAnalyzer
from engine.analysis import ExecutionTraceAnalyzer
from engine.environment import FuzzingEnvironment
from engine.operators import LinearRankingSelection
from engine.operators import DataDependencyLinearRankingSelection
from engine.operators import Crossover
from engine.operators import DataDependencyCrossover
from engine.operators import Mutation
from engine.fitness import fitness_function
from utils import settings
from utils.source_map import SourceMap
from utils.utils import initialize_logger, compile, get_interface_from_abi, get_pcs_and_jumpis, \
    get_function_signature_mapping
from utils.control_flow_graph import ControlFlowGraph


class Fuzzer:
    # 这个构造函数的主要目的是对模糊测试进行设置和初始化，包括日志、控制流图、合约信息、EVM环境和其他所需的结构。
    # 这样，当我们调用run方法时，所有必要的部件都已经准备好了，可以开始进行模糊测试。
    # 在创建Fuzzer对象时被调用
    # 参数说明：
    ## contract_name: 智能合约的名称
    ## abi: 智能合约的应用二进制接口（ABI），是一个JSON格式，描述了合约的接口。
    ## deployment_bytecode: 用于部署合约的字节码。
    ## runtime_bytecode: 合约在以太坊虚拟机（EVM）上运行时的字节码。
    ## test_instrumented_evm: 测试时使用的带仪表的EVM实例。
    ## blockchain_state: 初始区块链状态，可能是一系列交易。
    ## solver: 用于求解约束的Z3求解器实例。
    ## args: 命令行参数或其他配置。
    ## seed: 随机数生成器的种子。
    ## source_map (可选): 源码映射，用于定位源代码中的字节码。
    def __init__(self, contract_name, abi, deployment_bytecode, runtime_bytecode, test_instrumented_evm,
                 blockchain_state, solver, args, seed, source_map=None):
        global logger

        # 这里初始化了一个全局日志记录器，并记录了一个标题，表明开始对特定合约进行模糊测试。
        logger = initialize_logger("Fuzzer  ")
        logger.title("Fuzzing contract %s", contract_name)

        # 创建了一个控制流图（CFG）的实例，然后使用运行时字节码和EVM版本信息来构建这个图。
        # CFG是分析和优化智能合约的关键结构，因为它可以展示合约执行过程中的各种可能路径。
        cfg = ControlFlowGraph()
        cfg.build(runtime_bytecode, settings.EVM_VERSION)

        # 这一部分将传入的参数赋值给Fuzzer实例的属性。这包括合约的名称、接口、部署字节码、区块链状态、EVM实例和求解器。
        self.contract_name = contract_name
        self.interface = get_interface_from_abi(abi)
        self.deployement_bytecode = deployment_bytecode
        self.blockchain_state = blockchain_state
        self.instrumented_evm = test_instrumented_evm
        self.solver = solver
        self.args = args

        # Get some overall metric on the code
        # 获取字节码中的程序计数器（PC）和JUMPI指令位置，这对于了解合约的结构和确定跳转点非常有用。
        self.overall_pcs, self.overall_jumpis = get_pcs_and_jumpis(runtime_bytecode)

        # Initialize results
        # 初始化一个字典来存储测试结果，特别是任何错误。
        self.results = {"errors": {}}

        # Initialize fuzzing environment
        # 创建并初始化了一个模糊测试环境对象，传递了之前设置的所有相关参数，以及其他一些参数。
        # 这个环境将负责管理模糊测试期间的状态和配置。、
        # solver：用于约束求解
        # detector_executor：协调基于源映射和函数签名映射执行不同类型漏洞检测器的执行。
        # interface：智能合约的 ABI（应用程序二进制接口），描述了合约的函数和如何调用它们。
        # overall_pcs 和 overall_jumpis：分别存储字节码中程序计数器（PC）值和 JUMP 指令位置的集合。这些用于分析合约的控制流和可能的执行路径。
        # len_overall_pcs_with_children：初始化为零，这可能用于跟踪执行路径的长度，包括模糊测试期间发现的任何附加路径。
        # other_contracts：可能用于在模糊测试期间存储与之交互的其他合约的地址或信息的列表。
        self.env = FuzzingEnvironment(instrumented_evm=self.instrumented_evm,
                                      contract_name=self.contract_name,
                                      solver=self.solver,
                                      results=self.results,
                                      symbolic_taint_analyzer=SymbolicTaintAnalyzer(),
                                      detector_executor=DetectorExecutor(source_map,
                                                                         get_function_signature_mapping(abi)),
                                      interface=self.interface,
                                      overall_pcs=self.overall_pcs,
                                      overall_jumpis=self.overall_jumpis,
                                      len_overall_pcs_with_children=0,
                                      other_contracts=list(),
                                      args=args,
                                      seed=seed,
                                      cfg=cfg,
                                      abi=abi)

    def run(self):
        # 初始化要测试的智能合约的地址为None
        contract_address = None
        # 调用创建了一些假账户，这对于模拟一个真实的区块链环境是有用的
        self.instrumented_evm.create_fake_accounts()

        # 检查是否提供了源代码
        if self.args.source:
            # 如果提供了源码，则区块链状态也作为可选项，若提供了则遍历所有状态中的交易
            for transaction in self.blockchain_state:
                # 这段代码检查交易发送者地址是否已经在模拟的EVM账户列表中。
                # 如果不在，它将创建一个新的假账户并添加到账户列表中
                if transaction['from'].lower() not in self.instrumented_evm.accounts:
                    self.instrumented_evm.accounts.append(
                        self.instrumented_evm.create_fake_account(transaction['from']))
                # 这里检查to字段是否为空，这通常意味着要部署一个新合约。
                if not transaction['to']:
                    # 如果是这样，它将使用交易数据部署一个新合约。
                    # transaction['from']: 部署合约的账户地址。
                    # transaction['input']: 合约的部署数据，通常是编译后的合约字节码。
                    # transaction['value']: 交易中发送的以太币数量。
                    # transaction['gas'] 和 transaction['gasPrice']: 交易的燃气限额和燃气价格。
                    result = self.instrumented_evm.deploy_contract(transaction['from'], transaction['input'],
                                                                   int(transaction['value']), int(transaction['gas']),
                                                                   int(transaction['gasPrice']))
                    # 处理部署合约时可能出现的错误
                    if result.is_error:
                        logger.error("Problem while deploying contract %s using account %s. Error message: %s",
                                     self.contract_name, transaction['from'], result._error)
                        sys.exit(-2)
                    else:
                        # 将合约部署的结果（result.msg.storage_address）转换为十六进制格式，并将其赋值给contract_address变量。
                        # storage_address通常是新部署的智能合约的地址
                        contract_address = encode_hex(result.msg.storage_address)
                        # 将新部署的合约地址添加到模拟的EVM账户列表中。
                        # 这对于后续的交易模拟和合约与合约之间的交互是重要的。
                        self.instrumented_evm.accounts.append(contract_address)
                        # 在环境变量中增加交易数量的计数器。这表示已经成功执行了一次合约部署。
                        self.env.nr_of_transactions += 1
                        # 使用日志记录器输出一条调试信息，表明合约已在特定地址部署。
                        logger.debug("Contract deployed at %s", contract_address)
                        # 将新部署的合约地址转换为规范格式，并添加到环境变量中的其他合约列表中。这有助于跟踪测试过程中涉及的所有合约。
                        self.env.other_contracts.append(to_canonical_address(contract_address))
                        # 调用get_pcs_and_jumpis函数，获取新部署合约的程序计数器（PC）和JUMP指令的位置。
                        # 这些信息对于理解合约的控制流程是重要的。
                        cc, _ = get_pcs_and_jumpis(
                            self.instrumented_evm.get_code(to_canonical_address(contract_address)).hex())
                        # 将获取到的程序计数器数量加到环境变量的len_overall_pcs_with_children属性上。
                        # 这可能用于跟踪合约的复杂性或控制流的分支数量。
                        self.env.len_overall_pcs_with_children += len(cc)
                else:
                    # 初始化一个空字典，用于构建后续的交易输入
                    input = {}
                    # 在input字典中创建一个名为block的键，其值为空字典。
                    # 这里可能用于存储与区块相关的信息，例如区块号或时间戳，但在这个代码段中未设置具体值。
                    input["block"] = {}
                    # 设置transaction键的值，这是一个包含交易相关信息的字典
                    input["transaction"] = {
                        "from": transaction["from"],
                        "to": transaction["to"],
                        "gaslimit": int(transaction["gas"]),
                        "value": int(transaction["value"]),
                        "data": transaction["input"]
                    }
                    # 创建一个global_state键，其值也是一个空字典。
                    # 这可能用于记录全局状态，如其他账户的信息或者整个区块链的状态，但在这里未具体使用。
                    input["global_state"] = {}
                    # 使用上述构建的input字典以及交易的gasPrice调用deploy_transaction方法。
                    # 这个方法在模拟的EVM中执行交易。
                    out = self.instrumented_evm.deploy_transaction(input, int(transaction["gasPrice"]))

            # 检查智能合约的ABI（应用程序二进制接口）中是否存在构造函数（constructor）。
            # 如果存在，就从接口中删除它。构造函数在合约部署后不再需要，因此在初始化合约后将其从ABI中移除。
            if "constructor" in self.interface:
                del self.interface["constructor"]

            # 如果contract_address为空，也就是上面区块链状态设置中不含有合约部署
            if not contract_address:
                # 若没有构造器
                if "constructor" not in self.interface:
                    # 部署合约，这里指的是部署待测试的合约
                    result = self.instrumented_evm.deploy_contract(self.instrumented_evm.accounts[0],
                                                                   self.deployement_bytecode)
                    # 如果部署过程中出现错误，将记录错误信息并退出程序。
                    # sys.exit(-2)表示以错误状态结束程序。
                    if result.is_error:
                        logger.error("Problem while deploying contract %s using account %s. Error message: %s",
                                     self.contract_name, self.instrumented_evm.accounts[0], result._error)
                        sys.exit(-2)
                    else:
                        # 部署成功
                        # 更新contract_address为新部署的合约地址
                        # 将这个地址添加到账户列表中，增加交易计数，然后记录部署的合约地址
                        contract_address = encode_hex(result.msg.storage_address)
                        self.instrumented_evm.accounts.append(contract_address)
                        self.env.nr_of_transactions += 1
                        logger.debug("Contract deployed at %s", contract_address)

            # 检查合约地址是否在账户列表中，如果是，则将其移除。
            # 这可能是为了避免在后续的测试中将合约地址误用为普通账户。
            if contract_address in self.instrumented_evm.accounts:
                self.instrumented_evm.accounts.remove(contract_address)

            # 获取了新部署合约的程序计数器（PC）和JUMP指令的位置，这对于理解合约的控制流程非常重要。
            # 这些信息存储在环境变量中，可能用于后续的分析和决策。
            self.env.overall_pcs, self.env.overall_jumpis = get_pcs_and_jumpis(
                self.instrumented_evm.get_code(to_canonical_address(contract_address)).hex())

        # 如果提供了abi编码
        if self.args.abi:
            # 则将合约地址赋值为self.args.contract，这意味着在这种情况下，合约已经部署在区块链上，不需要进行部署操作
            contract_address = self.args.contract

        # 下面是模糊测试的逻辑

        # 创建模拟EVM的状态快照。这在模糊测试中非常有用，
        # 因为可以在执行每个测试用例后重置EVM的状态到这个快照，确保每次测试的独立性。
        self.instrumented_evm.create_snapshot()

        # 初始化一个Generator对象，用于生成模糊测试用例。
        # 它需要合约的接口、字节码、账户列表和合约地址。
        generator = Generator(interface=self.interface,
                              bytecode=self.deployement_bytecode,
                              accounts=self.instrumented_evm.accounts,
                              contract=contract_address)

        # Create initial population
        # 计算初始种群的大小，然后创建一个Population对象。
        # 种群中的每个个体（Individual）都由generator生成。
        # 种群的大小是一个配置项，如果未设置，则默认为接口数量的两倍。
        size = 2 * len(self.interface)
        population = Population(indv_template=Individual(generator=generator),
                                indv_generator=generator,
                                size=settings.POPULATION_SIZE if settings.POPULATION_SIZE else size).init()

        # Create genetic operators
        # 这段代码是在设置进化模糊测试引擎中使用的遗传算子，这些算子负责在模糊测试过程中生成、选择和变异测试用例。
        # 根据是否启用数据依赖性分析（data_dependency），它选择使用不同的选择和交叉算子。

        # 如果启用了数据依赖性分析
        if self.args.data_dependency:
            # 在数据依赖性分析被启用的情况下，使用DataDependencyLinearRankingSelection作为选择算子。
            # 这种选择算子可能会考虑测试用例之间的数据依赖关系来改善选择过程。
            selection = DataDependencyLinearRankingSelection(env=self.env)
            # 使用DataDependencyCrossover作为交叉算子，它考虑测试用例之间的数据依赖性来指导交叉过程。
            # pc参数是交叉发生的概率，从设置中获取。
            crossover = DataDependencyCrossover(pc=settings.PROBABILITY_CROSSOVER, env=self.env)
            # 无论是否启用数据依赖性分析，都使用相同的变异算子Mutation。pm参数是变异发生的概率。
            mutation = Mutation(pm=settings.PROBABILITY_MUTATION)
        # 若没有启用数据依赖性分析
        else:
            # 如果没有启用数据依赖性分析，将使用标准的选择和交叉算子，通常基于适应度值来排序和选择个体。
            selection = LinearRankingSelection()
            # 使用标准的Crossover算子作为交叉算子。这种算子不考虑数据依赖性，仅基于设定的交叉概率执行交叉。
            crossover = Crossover(pc=settings.PROBABILITY_CROSSOVER)
            # 无论是否启用数据依赖性分析，都使用相同的变异算子Mutation。pm参数是变异发生的概率。
            mutation = Mutation(pm=settings.PROBABILITY_MUTATION)

        # Create and run our evolutionary fuzzing engine
        # 这行代码初始化了一个进化模糊测试引擎（EvolutionaryFuzzingEngine），
        # 它是执行模糊测试的核心组件。传递给引擎的参数包括：
        # population：测试用例的初始种群。
        # selection、crossover、mutation：选择、交叉和变异算子，用于进化种群。
        # mapping：函数签名映射，这通过get_function_signature_mapping(self.env.abi)获取，可能用于辅助测试用例的生成和分析。
        engine = EvolutionaryFuzzingEngine(population=population, selection=selection, crossover=crossover,
                                           mutation=mutation, mapping=get_function_signature_mapping(self.env.abi))
        # 注册一个适应度评估函数，使用fitness_function函数，并且传递参数x，这里的x表示的是单个测试用例(个体)
        engine.fitness_register(lambda x: fitness_function(x, self.env))
        # 将执行追踪分析器（ExecutionTraceAnalyzer）添加到模糊测试引擎的分析模块中。
        # 这个分析器负责分析智能合约执行的追踪信息，以便发现潜在的漏洞或问题。
        engine.analysis.append(ExecutionTraceAnalyzer(self.env))

        # 记录模糊测试开始的时间，并将当前的种群状态保存到环境中。这有助于跟踪测试的持续时间和进度。
        self.env.execution_begin = time.time()
        self.env.population = population

        # 启动模糊测试引擎。ng参数指定了引擎运行的代数，即进行多少轮测试用例的生成、评估和进化。
        # 这个值从设置（settings.GENERATIONS）中获取。
        engine.run(ng=settings.GENERATIONS)

        # 这部分代码根据设置保存智能合约的控制流图（CFG）。
        # 如果启用了CFG功能（self.env.args.cfg为真），则根据是否提供了源代码或ABI，选择不同的路径来保存CFG。
        # 保存的格式是PDF，文件名基于合约名称和源文件或ABI文件的位置。
        if self.env.args.cfg:
            if self.env.args.source:
                self.env.cfg.save_control_flow_graph(
                    os.path.splitext(self.env.args.source)[0] + '-' + self.contract_name, 'pdf')
            elif self.env.args.abi:
                self.env.cfg.save_control_flow_graph(
                    os.path.join(os.path.dirname(self.env.args.abi), self.contract_name), 'pdf')

        self.instrumented_evm.reset()


def main():
    # 打印logo
    print_logo()
    # 解析命令行参数，并将解析后的参数存储在args变量中。
    args = launch_argument_parser()

    # 初始化日志记录器，用于整个程序的日志记录。
    logger = initialize_logger("Main    ")

    # Check if contract has already been analyzed
    # 检查是否指定了结果文件(args.results)，如果该文件已存在，则删除它并记录一条信息。
    # 这是为了避免重复分析同一合约。
    if args.results and os.path.exists(args.results):
        os.remove(args.results)
        logger.info("Contract " + str(args.source) + " has already been analyzed: " + str(args.results))
        sys.exit(0)

    # Initializing random
    # 设置随机数生成器的种子。如果提供了种子(args.seed)，使用它；
    # 否则，生成一个随机种子。这确保了测试的可重复性。
    if args.seed:
        seed = args.seed
        if not "PYTHONHASHSEED" in os.environ:
            logger.debug("Please set PYTHONHASHSEED to '1' for Python's hash function to behave deterministically.")
    else:
        seed = random.random()
    random.seed(seed)
    logger.title("Initializing seed to %s", seed)

    # 创建一个模拟的以太坊虚拟机（EVM）实例，并根据设置中指定的EVM版本配置它。
    instrumented_evm = InstrumentedEVM(settings.RPC_HOST, settings.RPC_PORT)
    instrumented_evm.set_vm_by_name(settings.EVM_VERSION)

    # Create Z3 solver instance
    # 初始化一个Z3求解器实例，并为其设置超时时间。
    solver = Solver()
    solver.set("timeout", settings.SOLVER_TIMEOUT)

    # Parse blockchain state if provided
    # 解析提供的区块链状态信息。
    # 初始化一个空列表blockchain_state。
    blockchain_state = []
    # 检查args.blockchain_state是否被指定。如果被指定，它可能是一个文件路径或一个表示区块高度的数字。
    if args.blockchain_state:
        # 如果args.blockchain_state是一个以".json"结尾的字符串，那么它被视为一个JSON文件的路径。
        if args.blockchain_state.endswith(".json"):
            # 使用with open(...) as json_file打开这个JSON文件，并逐行读取。
            with open(args.blockchain_state) as json_file:
                for line in json_file.readlines():
                    # 对于文件中的每一行，使用json.loads(line)将其从JSON格式转换为Python对象，并将这些对象添加到blockchain_state列表中。
                    blockchain_state.append(json.loads(line))
        # 如果args.blockchain_state是一个数字字符串，那么它被视为一个区块高度。
        elif args.blockchain_state.isnumeric():
            # 将这个字符串转换为整数，并设置为settings.BLOCK_HEIGHT
            settings.BLOCK_HEIGHT = int(args.blockchain_state)
            # 调用instrumented_evm.set_vm(settings.BLOCK_HEIGHT)设置模拟EVM的状态为特定的区块高度
            instrumented_evm.set_vm(settings.BLOCK_HEIGHT)
        else:
            logger.error("Unsupported input file: " + args.blockchain_state)
            sys.exit(-1)

    # Compile source code to get deployment bytecode, runtime bytecode and ABI
    # 检查是否通过命令行参数提供了源代码路径
    if args.source:
        # 如果源代码文件的扩展名为.sol，即Solidity源文件，继续执行后续代码
        if args.source.endswith(".sol"):
            # 调用compile函数，传递Solidity编译器的版本(args.solc_version)、
            # 以太坊虚拟机的版本(settings.EVM_VERSION)以及源代码文件路径，以编译智能合约。
            # 变量接收编译结果，这通常包括ABI、部署字节码和运行时字节码
            compiler_output = compile(args.solc_version, settings.EVM_VERSION, args.source)
            output_filename = 'compiler_output.json'
            with open(output_filename, 'w') as file:
                # 将数据以 JSON 格式写入文件
                json.dump(compiler_output, file, indent=4)
            # 如果没有编译输出（可能由于编译错误），记录错误信息并退出程序
            if not compiler_output:
                logger.error("No compiler output for: " + args.source)
                sys.exit(-1)
            # 遍历编译输出中的每个合约。编译结果可能包含一个源文件中的多个合约
            for contract_name, contract in compiler_output['contracts'][args.source].items():
                # 如果指定了特定的合约名称(args.contract)，且当前合约名称不匹配，则跳过当前循环迭代。
                if args.contract and contract_name != args.contract:
                    continue
                # 检查每个合约是否有有效的ABI、部署字节码和运行时字节码。
                if contract['abi'] and contract['evm']['bytecode']['object'] and contract['evm']['deployedBytecode'][
                    'object']:
                    # 如果这些都存在，创建一个SourceMap实例，用于映射源代码和编译后的字节码。
                    source_map = SourceMap(':'.join([args.source, contract_name]), compiler_output)
                    # 创建Fuzzer实例，传入合约名称、ABI、字节码等信息，并调用其run方法来执行模糊测试。
                    Fuzzer(contract_name, contract["abi"], contract['evm']['bytecode']['object'],
                           contract['evm']['deployedBytecode']['object'], instrumented_evm, blockchain_state, solver,
                           args, seed, source_map).run()
        else:
            logger.error("Unsupported input file: " + args.source)
            sys.exit(-1)

    # 当提供的是合约的abi文件时
    if args.abi:
        # 打开abi文件
        with open(args.abi) as json_file:
            abi = json.load(json_file)
            # 将提供的合约地址转换为规范格式,从模拟的以太坊虚拟机（EVM）中获取指定地址的合约代码,
            # 将获取到的字节码转换为十六进制字符串，这是智能合约的运行时字节码
            runtime_bytecode = instrumented_evm.get_code(to_canonical_address(args.contract)).hex()
            if not runtime_bytecode:
                # runtime_bytecode为空，可能表示指定地址没有部署的合约
                logger.error("No contract code found at address: " + args.contract)
                # 可以选择退出程序或者执行其他适当的错误处理逻辑
                sys.exit(1)
            else:
                # 创建Fuzzer类的一个实例，用于执行模糊测试
                # 向Fuzzer的构造函数传递合约地址（args.contract）、ABI（abi）、
                # 部署字节码（这里是None，因为合约已部署）、运行时字节码、
                # 模拟的EVM实例、区块链状态、求解器实例、命令行参数和种子值。
                Fuzzer(args.contract, abi, None, runtime_bytecode, instrumented_evm, blockchain_state, solver, args,
                       seed).run()


# 命令行参数解析
def launch_argument_parser():
    # 创建一个ArgumentParser对象，用于处理命令行参数
    parser = argparse.ArgumentParser()

    # Contract parameters
    # 定义了一个互斥参数组group1，其中包含--source和--abi。
    # 用户必须提供这两个参数中的一个，但不能同时提供。
    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument("-s", "--source", type=str,
                        help="通过源代码文件进行测试 (.sol).")
    group1.add_argument("-a", "--abi", type=str,
                        help="通过ABI文件进行测试 (.json).")

    # group2 = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("-c", "--contract", type=str,
                        help="若通过源代码文件测试，则提供待测合约名称；若通过ABI测试，则提供待测合约地址.")

    parser.add_argument("-b", "--blockchain-state", type=str,
                        help="若通过源代码文件测试，则提供状态文件（.json）；若通过ABI测试，则提供区块高度.")

    # Compiler parameters
    parser.add_argument("--solc", help="Solidity编译器版本设置 (默认 '" + str(
        solcx.get_solc_version()) + "'). 已下载编译器版本: " + str(solcx.get_installed_solc_versions()) + ".",
                        action="store", dest="solc_version", type=str)
    parser.add_argument("--evm", help="以太坊虚拟机版本设置 (default '" + str(
        settings.EVM_VERSION) + "'). 可用的虚拟机版本: 'homestead', 'byzantium' or 'petersburg'.", action="store",
                        dest="evm_version", type=str)

    # Evolutionary parameters
    # 定义了另一个互斥参数组group3，包含--generations和--timeout
    group3 = parser.add_mutually_exclusive_group(required=False)
    group3.add_argument("-g", "--generations",
                        help="迭代层数（终止条件） (默认 " + str(settings.GENERATIONS) + ").", action="store",
                        dest="generations", type=int)
    group3.add_argument("-t", "--timeout",
                        help="终止时间（终止条件）.", action="store",
                        dest="global_timeout", type=int)
    parser.add_argument("-n", "--population-size",
                        help="种群大小.", action="store",
                        dest="population_size", type=int)
    parser.add_argument("-pc", "--probability-crossover",
                        help="交叉概率.", action="store",
                        dest="probability_crossover", type=float)
    parser.add_argument("-pm", "--probability-mutation",
                        help="变异概率.", action="store",
                        dest="probability_mutation", type=float)

    # Miscellaneous parameters

    parser.add_argument("-r", "--results", type=str, help="指定结果存储路径")
    parser.add_argument("--seed", type=float, help="通过给定的种子初始化随机数生成器.")
    parser.add_argument("--cfg", help="构建控制流图并突出显示代码覆盖率", action="store_true")
    parser.add_argument("--rpc-host", help="以太坊 RPC主机名.", action="store", dest="rpc_host", type=str)
    parser.add_argument("--rpc-port", help="以太坊 RPC端口号.", action="store", dest="rpc_port", type=int)

    parser.add_argument("--data-dependency",
                        help="是否启动数据依赖项分析，默认为1(0:不启动 ，1:启动)", action="store",
                        dest="data_dependency", type=int)
    parser.add_argument("--constraint-solving",
                        help="是否启动约束求解，默认为1(0:不启动，1：启动)", action="store",
                        dest="constraint_solving", type=int)
    parser.add_argument("--environmental-instrumentation",
                        help="是否启动环境监测,默认为1(0：不启动，1：启动)", action="store",
                        dest="environmental_instrumentation", type=int)
    parser.add_argument("--max-individual-length",
                        help="设置最大个体长度 (默认: " + str(settings.MAX_INDIVIDUAL_LENGTH) + ")", action="store",
                        dest="max_individual_length", type=int)
    parser.add_argument("--max-symbolic-execution",
                        help="设置重置种群之前符号执行的最大次数 (默认: " + str(settings.MAX_SYMBOLIC_EXECUTION) + ")",
                        action="store",
                        dest="max_symbolic_execution", type=int)

    version = "YuanShen - Version 0.0.1 - "
    version += "\"By three methods we may learn wisdom:\n"
    version += "First, by reflection, which is noblest;\n"
    version += "Second, by imitation, which is easiest;\n"
    version += "And third by experience, which is the bitterest.\"\n"
    parser.add_argument("-v", "--version", action="version", version=version)

    # 解析命令行输入的参数
    args = parser.parse_args()

    # 如果没有指定合约，则将其设置为空字符串
    if not args.contract:
        args.contract = ""

    # 如果用户通过--source指定了Solidity源文件，那么通过--contract指定的值不应该是一个以0x开头的地址。
    if args.source and args.contract.startswith("0x"):
        parser.error("--source requires --contract to be a name, not an address.")
    # 如果用户同时指定了--source（Solidity源文件）和--blockchain-state，那么--blockchain-state指定的值应该是一个文件路径而不是一个数字。
    if args.source and args.blockchain_state and args.blockchain_state.isnumeric():
        parser.error("--source requires --blockchain-state to be a file, not a number.")

    if args.abi and not args.contract.startswith("0x"):
        parser.error("--abi requires --contract to be an address, not a name.")
    if args.abi and args.blockchain_state and not args.blockchain_state.isnumeric():
        parser.error("--abi requires --blockchain-state to be a number, not a file.")

    # 根据提供的参数设置全局配置
    if args.evm_version:
        settings.EVM_VERSION = args.evm_version
    if not args.solc_version:
        args.solc_version = solcx.get_solc_version()
    if args.generations:
        settings.GENERATIONS = args.generations
    if args.global_timeout:
        settings.GLOBAL_TIMEOUT = args.global_timeout
    if args.population_size:
        settings.POPULATION_SIZE = args.population_size
    if args.probability_crossover:
        settings.PROBABILITY_CROSSOVER = args.probability_crossover
    if args.probability_mutation:
        settings.PROBABILITY_MUTATION = args.probability_mutation

    if args.data_dependency == None:
        args.data_dependency = 1
    if args.constraint_solving == None:
        args.constraint_solving = 1
    if args.environmental_instrumentation == None:
        args.environmental_instrumentation = 1

    if args.environmental_instrumentation == 1:
        settings.ENVIRONMENTAL_INSTRUMENTATION = True
    elif args.environmental_instrumentation == 0:
        settings.ENVIRONMENTAL_INSTRUMENTATION = False

    if args.max_individual_length:
        settings.MAX_INDIVIDUAL_LENGTH = args.max_individual_length
    if args.max_symbolic_execution:
        settings.MAX_SYMBOLIC_EXECUTION = args.max_symbolic_execution

    # 如果为abi测试模式，则开启远程模糊测试配置
    if args.abi:
        settings.REMOTE_FUZZING = True

    if args.rpc_host:
        settings.RPC_HOST = args.rpc_host
    if args.rpc_port:
        settings.RPC_PORT = args.rpc_port

    return args


def print_logo():
    print(" _   _                 _   _              _  ")
    print("| | | | ___  _ __ ___ | | | |  ___   _ __| | ")
    print("| |_| |/ _ \| '_ ` _ \| | | | / _ \ | '__| | ")
    print("|  _  | (_) | | | | | | | | || (_) || |  | | ")
    print("|_| |_|\___/|_| |_| |_|_| |_| \___/ |_|  |_| ")
    print("")


if '__main__' == __name__:
    main()
