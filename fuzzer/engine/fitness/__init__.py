#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 计算个体适应度值的函数
def fitness_function(indv, env):
    block_coverage_fitness = compute_branch_coverage_fitness(env.individual_branches[indv.hash], env.code_coverage)
    if env.args.data_dependency:
        data_dependency_fitness = compute_data_dependency_fitness(indv, env.data_dependencies)
        return block_coverage_fitness + data_dependency_fitness
    return block_coverage_fitness

# 计算个体测试用例的代码覆盖率适应度
def compute_branch_coverage_fitness(branches, pcs):
    non_visited_branches = 0.0

    # 遍历 branches 字典中的每个跳转指令位置 (jumpi)
    for jumpi in branches:
        # 对于每个 jumpi，再遍历其所有可能的跳转目的地
        for destination in branches[jumpi]:
            # 检查是否没有访问过这个分支（即 branches[jumpi][destination] 为 False）
            # 检查目的地地址是否不在 pcs 集合中（意味着在执行测试用例时没有访问过这个地址）
            if not branches[jumpi][destination] and destination not in pcs:
                # 如果这两个条件都成立，说明这是一个未被访问的分支，增加 non_visited_branches 计数
                non_visited_branches += 1

    return non_visited_branches

#
def compute_data_dependency_fitness(indv, data_dependencies):
    data_dependency_fitness = 0.0
    all_reads = set()

    for d in data_dependencies:
        all_reads.update(data_dependencies[d]["read"])

    for i in indv.chromosome:
        _function_hash = i["arguments"][0]
        if _function_hash in data_dependencies:
            for i in data_dependencies[_function_hash]["write"]:
                if i in all_reads:
                    data_dependency_fitness += 1

    return data_dependency_fitness
