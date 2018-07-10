#pragma once
#include "main.h"

typedef struct Chromosome
{
	short *genes;
	double fitness;
	int budget;
	int size;
}chromosome, *chromosome_p;

void initialize(chromosome population[], int pop_size, int genes, int budget);
void selection(chromosome population[], int population_size, int genes, int objective);
void crossover(chromosome population[], int parent1, int parent2, int offspring, int genes);
void mutation(chromosome population[], int population_size, double mutation_prob, int genes);
void restore_budget(chromosome population[], int population_size, int budget, int individual);
void delete_population(chromosome population[], int pop_size, int genes);
void show_strategy(chromosome population[], int individual, int genes);
void set_fitness_to_zero(chromosome population[], int pop_size);