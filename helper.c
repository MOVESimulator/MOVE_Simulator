#include "main.h"
#include "ga.h"
#include<vector>
using namespace std;

int get_random_int(int min, int max)
{
	return min + (int) ((double)(max - min + 1) * (rand() / (RAND_MAX + 1.0)));
}

double get_random_double()
{
	return rand() / (double) RAND_MAX;
}


int HW(int n)
{
	int i = 0;
	for (i = 0; n; i++) {
		n &= (n - 1);
	}
	return i;
}


void validate_command_line(int argc, char* argv[], char parameters[])
{
	puts("");
	puts("*********    Welcome To Adversarial Network CyberSecurity Game      *********");
	
	if (argc != 2 && argc != 4){
		puts("Incorrect number of arguments");
		exit(1);
	}
	if (argc == 2) {
		strcpy(parameters, argv[1]);
	}
	else {
		strcpy(parameters, argv[1]);
		strcpy(pre_adj, argv[2]);
		strcpy(pre_vul, argv[3]);
		preconfig = 1;
	}
}

void get_parameters(char parameters[])
{
	char	dummy[150];
	FILE*	fp;

	printf("\n********* Reading parameters defined in %s *********\n", parameters);
	fp = fopen(parameters, "r");
	if (!fp) {
		printf("Missing file: %s\n", parameters);
		exit(1);
	}

	fscanf(fp, "%u %s", &scenario, dummy);
	fscanf(fp, "%u %s", &runs, dummy);
	fscanf(fp, "%u %s", &generations, dummy);
	fscanf(fp, "%u %s", &games, dummy);
	fscanf(fp, "%u %s", &pop_size_attack, dummy);
	fscanf(fp, "%u %s", &pop_size_defense, dummy);

	fscanf(fp, "%u %s", &genotype_size_attacker, dummy);
	fscanf(fp, "%u %s", &genotype_size_defender, dummy);
	fscanf(fp, "%lf %s", &ind_mut_prob_attack, dummy);
	fscanf(fp, "%lf %s", &ind_mut_prob_defense, dummy);

	fscanf(fp, "%u %s", &max_honeypots, dummy);
	fscanf(fp, "%u %s", &attack_budget, dummy);
	fscanf(fp, "%u %s", &defense_budget, dummy);
	fscanf(fp, "%u %s", &attacker_node, dummy);
	fscanf(fp, "%u %s", &max_resources, dummy);
	fscanf(fp, "%u %s", &max_resources_per_host, dummy);
	fscanf(fp, "%u %s", &min_value, dummy);
	fscanf(fp, "%u %s", &max_value, dummy);

	fscanf(fp, "%u %s", &network_size, dummy);
	fscanf(fp, "%u %s", &nr_real_nodes, dummy);
	fscanf(fp, "%u %s", &max_network_size, dummy);
	fscanf(fp, "%u %s", &scan_cost, dummy);
	fscanf(fp, "%u %s", &diversify_resource, dummy);
	fscanf(fp, "%u %s", &defense_cost, dummy);
	fscanf(fp, "%llu %s", &seed, dummy);
	fscanf(fp, "%u %s", &type, dummy);
	fscanf(fp, "%lf %s", &network_sparsity, dummy);
	fscanf(fp, "%lf %s", &similarity_threshold, dummy);

	fscanf(fp, "%d %s", &attacker_objective, dummy);
	fscanf(fp, "%d %s", &defender_objective, dummy);

	fscanf(fp, "%u %s", &log_level, dummy);

	fscanf(fp, "%s %s", final_output_file, dummy);
	fscanf(fp, "%s %s", network_file, dummy);

	fclose(fp);

	if (network_size > max_network_size) {
		printf("Too large network\n");
		exit(0);
	}

	if (runs < 1) {
		puts("Number of runs must be at least 1");
		exit(0);
	}

	if (attacker_node > (int) network_size) {
		puts("Wrong attacker node\n");
		exit(0);
	}

	if (generations < 1){
		puts("Number of generations must be at least 1");
		exit(0);
	}

	if ((network_size * 1.5) > max_network_size) {
		puts("The max network size is too small to support network extension\n");
		exit(0);
	}

	if (attack_budget > 3 * network_size) {
		puts("Attack budget must be significantly smaller than the number of nodes in original network\n");
		exit(0);
	}

	if (nr_real_nodes > network_size) {
		puts("The number of fixed nodes cannot be less than the network size\n");
		exit(0);
	}

	if (pop_size_attack < 3 || pop_size_defense < 3) {
		puts("Population size needs to be at least 3\n");
		exit(0);
	}

	if (seed == 0) {
		srand((uint)time(NULL));
	}
	else {
		srand((uint)seed);
	}

	puts("********* Beginning execution *********");
}



void get_resource_similarity(vector< vector<double> >& res_similarity, int size)
{
	double temp = 0.0;
	for (int i = 0; i < size; i++) {
		for (int j = 0; j < size; j++) {
			if (i == j) {
				res_similarity[i][j] = 1.0;
			}
			else {
				temp = get_random_double();
				res_similarity[i][j] = temp;
				res_similarity[j][i] = temp;
			}
		}
	}
}


void get_vulnerability_cost(int *exploit_cost, int size, int budget)
{
	for (int i = 0; i < size; i++) {
		exploit_cost[i] = get_random_int(1, (int)budget / 3);
	}
}

void logging(char *name, int log_level, int generation, chromosome population[], int pop_size, char *pop)
{
	FILE *fout;
	int log = 0;

	if (generation == 1) {
		if ((fout = fopen(name, "w+")) == NULL) {
			puts("Error opening log file\n");
			exit(0);
		}
	}
	else {
		if ((fout = fopen(name, "a+")) == NULL) {
			puts("Error opening log file\n");
			exit(0);
		}
	}
		
	if ((generation % log_level) == 0) {
		fprintf(fout, "%s, generation %d\n", pop, generation);

		for (int j = 0; j < pop_size; j++) {
			fprintf(fout, "Individual %d\t", j + 1);
			for (int i = 0; i < population[j].size; i++) {
				fprintf(fout, "|%d|", population[j].genes[i]);
			}
			fprintf(fout, "\tFitness: %.3lf\n", population[j].fitness);
		}

		double min = 0.0;
		double max = 0.0;
		double avg = 0.0;
		double stdev = 0.0;


		min = population[0].fitness;
		max = population[0].fitness;
		for (int i = 0; i < pop_size; i++) {
			if (population[i].fitness > max) {
				max = population[i].fitness;
			}
			if (population[i].fitness < min) {
				min = population[i].fitness;
			}
			avg += population[i].fitness;
		}

		avg = avg / pop_size;

		for (int i = 0; i < pop_size; i++) {
			stdev += (population[i].fitness - avg)*(population[i].fitness - avg);
		}

		stdev = sqrt(stdev / pop_size);

		fprintf(fout, "Current stats\t%.3lf\t%.3lf\t%.3lf\t%.3lf\t%d\n", min, max, avg, stdev, generations);
		fprintf(fout, "\n\n");
	}
	fclose(fout);
}


void final_stats(char *name, int run, chromosome defenders[], int pop_size_defense, chromosome attackers[], int pop_size_attack, int generations)
{
	FILE *fout;
	double min = 0.0;
	double max = 0.0;
	double avg = 0.0;
	double stdev = 0.0;

	if (run == 1) {
		if ((fout = fopen(name, "w+")) == NULL) {
			puts("Error opening log file\n");
			exit(0);
		}
	}
	else {
		if ((fout = fopen(name, "a+")) == NULL) {
			puts("Error opening log file\n");
			exit(0);
		}
	}

	if (run == 1) {
		fprintf(fout, "Run\tPopulation\tMin\tMax\tAvg\tStdDev\tGenerations\n");
	}

	min = defenders[0].fitness;
	max = defenders[0].fitness;
	for (int i = 0; i < pop_size_defense; i++) {
		if (defenders[i].fitness > max) {
			max = defenders[i].fitness;
		}
		if (defenders[i].fitness < min) {
			min = defenders[i].fitness;
		}
			avg += defenders[i].fitness;
	}

	avg = avg / pop_size_defense;

	for (int i = 0; i < pop_size_defense; i++) {
		stdev += (defenders[i].fitness - avg)*(defenders[i].fitness - avg);
	}

	stdev = sqrt(stdev / pop_size_defense);

	fprintf(fout, "%d\tDefense\t%.3lf\t%.3lf\t%.3lf\t%.3lf\t%d\n", run, min, max, avg, stdev, generations);

	min = attackers[0].fitness;
	max = attackers[0].fitness;
	avg = 0.0;
	stdev = 0.0;
	for (int i = 0; i < pop_size_attack; i++) {
		if (attackers[i].fitness > max) {
			max = attackers[i].fitness;
		}
		if (attackers[i].fitness < min) {
			min = attackers[i].fitness;
		}
		avg += attackers[i].fitness;
	}
	avg = avg / pop_size_attack;

	for (int i = 0; i < pop_size_attack; i++) {
		stdev += (attackers[i].fitness - avg)*(attackers[i].fitness - avg);
	}

	stdev = sqrt(stdev / pop_size_attack);

	fprintf(fout, "%d\tAttack\t%.3lf\t%.3lf\t%.3lf\t%.3lf\t%d\n", run, min, max, avg, stdev, generations);
	fclose(fout);
}