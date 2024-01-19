#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from random import random, shuffle, choice
from itertools import accumulate
from bisect import bisect_right

from ...plugin_interfaces.operators.selection import Selection

# 线性选择算子，使用线性排名的方式选择种群中的个体(即测试用例)，目的是从当前种群中选出优质的个体，以便他们能够进行交叉和变异。
class LinearRankingSelection(Selection):
    # pmin：最差个体选择概率
    # pmax：最佳个体选择概率
    def __init__(self, pmin=0.1, pmax=0.9):
        '''
        Selection operator using Linear Ranking selection method.
        Reference: Baker J E. Adaptive selection methods for genetic
        algorithms[C]//Proceedings of an International Conference on Genetic
        Algorithms and their applications. 1985: 101-111.
        '''
        # Selection probabilities for the worst and best individuals.
        self.pmin, self.pmax = pmin, pmax

    # 选择方法
    def select(self, population, fitness):
        '''
        Select a pair of parent individuals using linear ranking method.
        '''

        # Add rank to all individuals in population.
        all_fits = population.all_fits(fitness)
        indvs = population.individuals
        sorted_indvs = sorted(indvs, key=lambda indv: all_fits[indvs.index(indv)])

        # Individual number.
        NP = len(population)

        # Assign selection probabilities linearly.
        # NOTE: Here the rank i belongs to {1, ..., N}
        p = lambda i: (self.pmin + (self.pmax - self.pmin)*(i-1)/(NP-1))
        probabilities = [self.pmin] + [p(i) for i in range(2, NP)] + [self.pmax]

        # Normalize probabilities.
        psum = sum(probabilities)
        wheel = list(accumulate([p/psum for p in probabilities]))

        # Select parents.
        father_idx = bisect_right(wheel, random())
        father = sorted_indvs[father_idx]
        mother_idx = (father_idx + 1) % len(wheel)
        mother = sorted_indvs[mother_idx]

        return father, mother
