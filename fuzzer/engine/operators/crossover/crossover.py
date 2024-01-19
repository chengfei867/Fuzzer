#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' Crossover operator implementation. '''

import random

from utils import settings
from ...plugin_interfaces.operators.crossover import Crossover
from ...components.individual import Individual

# 交叉（杂交）产生新个体的方法，通过结合两个（或更多个）父代个体的特征来完成
class Crossover(Crossover):
    # pc：交叉概率
    def __init__(self, pc):
        '''
        :param pc: The probability of crossover (usaully between 0.25 ~ 1.0)
        :type pc: float in (0.0, 1.0]
        '''
        if pc <= 0.0 or pc > 1.0:
            raise ValueError('Invalid crossover probability')

        self.pc = pc

    # 这个方法接收两个个体（父代）作为输入，并返回两个新的个体（子代）
    def cross(self, father, mother):
        '''
        Cross the selected individuals.
        '''

        do_cross = True if random.random() <= self.pc else False

        if mother is None:
            return father.clone(), father.clone()

        _father = father.clone()
        _mother = mother.clone()

        if not do_cross or len(father.chromosome) + len(mother.chromosome) > settings.MAX_INDIVIDUAL_LENGTH:
            return _father, _mother

        child1 = Individual(generator=_father.generator)
        child1.init(chromosome=_father.chromosome + _mother.chromosome)

        child2 = Individual(generator=_mother.generator)
        child2.init(chromosome=_mother.chromosome + _father.chromosome)

        return child1, child2
