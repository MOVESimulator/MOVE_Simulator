#include "main.h"
#include "ga.h"
#include "helper.h"

void initialize(chromosome population[], int pop_size, int genes, int budget)
{
	for (int j = 0; j < pop_size; j++) {
		population[j].genes = (short *)malloc(sizeof(short) * genes);
		for (int i = 0; i < genes; i++) {
			population[j].genes[i] = get_random_int(min_value, max_value);
		}
		population[j].budget = budget;
		population[j].size = genes;
	}
}

void selection(chromosome population[], int population_size, int genes, int objective)
{
	int temp, parent1 = 0, parent2 = 0, offspring = 0;
	for (int i = 0; i < population_size; i++) {
		parent1 = get_random_int(0, population_size - 1);
		parent2 = get_random_int(0, population_size - 1);

		while (parent1 == parent2)
			parent1 = get_random_int(0, population_size - 1);

		offspring = get_random_int(0, population_size - 1);

		while ((offspring == parent1) || (offspring == parent2))
			offspring = get_random_int(0, population_size - 1);

		if (objective == 1) {
			if (population[offspring].fitness > population[parent1].fitness) {
				temp = offspring;
				offspring = parent1;
				parent1 = temp;
			}
			if (population[offspring].fitness > population[parent2].fitness) {
				temp = offspring;
				offspring = parent2;
				parent2 = temp;
			}
		}
		else {
			if (population[offspring].fitness < population[parent1].fitness) {
				temp = offspring;
				offspring = parent1;
				parent1 = temp;
			}
			if (population[offspring].fitness < population[parent2].fitness) {
				temp = offspring;
				offspring = parent2;
				parent2 = temp;
			}
		}
		
		crossover(population, parent1, parent2, offspring, genes);
	}
}

void crossover(chromosome population[], int parent1, int parent2, int offspring, int genes)
{
	int random;
	int i;
	random = get_random_int(0, genes);
	for (i = 0; i < random; i++)
		population[offspring].genes[i] = population[parent1].genes[i];

	for (i = random; i < genes; i++)
		population[offspring].genes[i] = population[parent2].genes[i];
}

void mutation(chromosome population[], int population_size, double mutation_prob, int genes)
{
	int i, j, random;
	int dont_touch = 0;
	double max = 0.0;
	for (int i = 0; i < population_size; i++) {
		if (population[i].fitness > max) {
			max = population[i].fitness;
			dont_touch = i;
		}
	}
	for (i = 0; i < population_size; i++) {
		if (i != dont_touch) {
			for (j = 0; j < genes; j++) {
				if (get_random_double() < mutation_prob) {
					random = get_random_int(min_value, max_value);
					population[i].genes[j] = random;
					break;
				}
			}
		}
	}
}

void restore_budget(chromosome population[], int population_size, int budget, int individual)
{
	if (individual == -1) {
		for (int i = 0; i < population_size; i++) {
			population[i].budget = budget;
		}
	}
	else {
		population[individual].budget = budget;
	}
}


void delete_population(chromosome population[], int pop_size, int genes)
{
	for (int i = 0; i < pop_size; i++) {
		free(population[i].genes);
	}
}


void set_fitness_to_zero(chromosome population[], int pop_size)
{
	for (int i = 0; i < pop_size; i++) {
		population[i].fitness = 0;
	}
}

//void show_strategy(chromosome population[], int individual, int genes)
//{
//	if (genes == 4) { //attacker
//		int spend_on_scanning = 0;
//		int spend_on_exploit = 0;
//		int bfs_scan = 0;
//		int dfs_scan = 0;
//		int exploit_diversify = 0;
//		int exploit_group = 0;
//		int path_strategy = 0;
//
//		spend_on_scanning = (int)(((double)population[individual].genes[0] / 100) * population[individual].budget);
//
//		spend_on_exploit = population[individual].budget - spend_on_scanning;
//
//		bfs_scan = (int)(((double)population[individual].genes[1] / 100) * spend_on_scanning);
//
//		dfs_scan = spend_on_scanning - bfs_scan;
//
//		exploit_diversify = (int)(((double)population[individual].genes[2] / 100) * spend_on_exploit);
//
//		exploit_group = spend_on_exploit - exploit_diversify;
//
//		path_strategy = population[individual].genes[3];
//
//		printf("Attack strategy consists of:\n");
//		printf("Use %d units on scan and %d on exploit\n", spend_on_scanning, spend_on_exploit);
//		printf("Use %d units on BFS and %d units on DFS\n", bfs_scan, dfs_scan);
//		printf("Use %d units for exploit diversification and %d units for grouping\n", exploit_diversify, exploit_group);
//		printf("Path strategy is ");
//		for (int i = 0; i < 8; i++) {
//			printf("%d ", (path_strategy >> i) & 1);
//		}
//		printf("\n");
//	}
//	else { //defender
//		1;
//	}
//}
