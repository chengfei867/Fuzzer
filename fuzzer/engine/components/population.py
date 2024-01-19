#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class Individuals(object):
    '''
    Descriptor for all individuals in population.
    '''
    def __init__(self, name):
        self.name = '_{}'.format(name)

    def __get__(self, instance, owner):
        return instance.__dict__[self.name]

    def __set__(self, instance, value):
        instance.__dict__[self.name] = value
        # Update flag.
        instance.update_flag()

class Population(object):
    # All individuals.
    individuals = Individuals('individuals')

    # 参数 indv_template 是用于克隆种群中所有其他个体的模板。
    # 参数 indv_generator 是一个用于生成个体的生成器。
    # 参数 size 指定了种群的大小（个体数量）。
    def __init__(self, indv_template, indv_generator, size=100):
        '''
        Class for representing population in genetic algorithm.

        :param indv_template: A template individual to clone all the other
                              individuals in current population.

        :param size: The size of population, number of individuals in population.
        :type size: int

        '''
        # Population size.
        if size % 2 != 0:
            raise ValueError('Population size must be an even number')
        self.size = size
        
        # Template individual.
        self.indv_template = indv_template

        # Generator individual.
        self.indv_generator = indv_generator

        # 监测种群变化的标识
        self._updated = False

        # Container for all individuals.
        # 存储种群个体的列表，可以自动更新self._updated标识
        class IndvList(list):
            '''
            A proxy class inherited from built-in list to contain all
            individuals which can update the population._updated flag
            automatically when its content is changed.
            '''
            # NOTE: Use 'this' here to avoid name conflict.
            def __init__(this, *args):
                super(this.__class__, this).__init__(*args)

            """def __setitem__(this, key, value):
                '''
                Override __setitem__ in built-in list type.
                '''
                old_value = this[key]
                if old_value == value:
                    return
                super(this.__class__, self).__setitem__(key, value)
                # Update population flag.
                self.update_flag()"""

            def append(this, item):
                '''
                Override append method of built-in list type.
                '''
                super(this.__class__, this).append(item)
                # Update population flag.
                self.update_flag()

            def extend(this, iterable_item):
                if not iterable_item:
                    return
                super(this.__class__, this).extend(iterable_item)
                # Update population flag.
                self.update_flag()
            # }}}

        self._individuals = IndvList()

    def init(self, indvs=None):
        '''
        Initialize current population with individuals.

        :param indvs: Initial individuals in population, randomly initialized
                      individuals are created if not provided.
        :type indvs: list of Individual object
        '''
        IndvType = self.indv_template.__class__

        if indvs is None:
            while len(self.individuals) < self.size:
                indv = IndvType(generator=self.indv_generator).init()
                self.individuals.append(indv)
        else:
            # Check individuals.
            if len(indvs) != self.size:
                raise ValueError('Invalid individuals number')
            for indv in indvs:
                if not isinstance(indv, SessionIndividual):
                    raise ValueError('individual class must be Individual or a subclass of Individual')
            self.individuals = indvs

        self._updated = True
        return self

    def update_flag(self):
        '''
        Interface for updating individual update flag to True.
        '''
        self._updated = True

    @property
    def updated(self):
        '''
        Query function for population updating flag.
        '''
        return self._updated

    def new(self):
        '''
        Create a new emtpy population.
        '''
        return self.__class__(indv_template=self.indv_template, size=self.size)

    def __getitem__(self, key):
        '''
        Get individual by index.
        '''
        if key < 0 or key >= self.size:
            raise IndexError('Individual index({}) out of range'.format(key))
        return self.individuals[key]

    def __len__(self):
        '''
        Get length of population.
        '''
        return len(self.individuals)

    def best_indv(self, fitness):
        '''
        The individual with the best fitness.

        '''
        all_fits = self.all_fits(fitness)
        return max(self.individuals, key=lambda indv: all_fits[self.individuals.index(indv)])

    def worst_indv(self, fitness):
        '''
        The individual with the worst fitness.
        '''
        all_fits = self.all_fits(fitness)
        return min(self.individuals, key=lambda indv: all_fits[self.individuals.index(indv)])

    def max(self, fitness):
        '''
        Get the maximum fitness value in population.
        '''
        return max(self.all_fits(fitness))

    def min(self, fitness):
        '''
        Get the minimum value of fitness in population.
        '''
        return min(self.all_fits(fitness))

    def mean(self, fitness):
        '''
        Get the average fitness value in population.
        '''
        all_fits = self.all_fits(fitness)
        return sum(all_fits)/len(all_fits)

    def all_fits(self, fitness):
        '''
        Get all fitness values in population.
        '''
        return [fitness(indv) for indv in self.individuals]
