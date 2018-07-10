#include "main.h"
#include "ga.h"
#include "network.h"
#include "helper.h"
#include "attacker.h"
#include "defender.h"

// global variables accesible to others:
unsigned long long  seed;

uint scenario;
uint  runs;
uint pop_size_attack;
uint pop_size_defense;
uint genotype_size_attacker;
uint genotype_size_defender;

double ind_mut_prob_attack;
double ind_mut_prob_defense;

uint generations;
uint games;

uint max_honeypots;
uint defense_budget;
uint attack_budget;
uint max_resources;
uint max_resources_per_host;

uint min_value;
uint max_value;

uint network_size;
uint nr_real_nodes;
uint max_network_size;
uint type;

uint scan_cost;
uint wait_cost;
uint defense_cost;

double network_sparsity;

char name[100];
char parameters[100];
char pre_adj[100];
char pre_vul[100];

vector< vector<double> > res_similarity;

int *exploit_cost;

int attacker_objective;
int defender_objective;

uint log_level;

char final_output_file[100];
char network_file[100];

int preconfig;

uint diversify_resource;

double similarity_threshold;

int attacker_node;

uint *resource_popularity;


void main(int argc, char* argv[])
{
	uint n, i;
	//check that the number of parameters is either 2 (when reading only config.txt) or 4 (when reading config.txt but also preconfigured network)
	validate_command_line(argc, argv, parameters);

	//Read all parameters from config.txt and ensure they are correct
	get_parameters(parameters);

	//create the basic network
	net_p base_network = create_network(UNDIRECTED, network_size, max_network_size, network_sparsity, preconfig);

	//create resources for basic network
	create_resources(base_network, max_resources, max_resources_per_host, preconfig);

	resource_popularity = (uint*)calloc(sizeof(double), (base_network->max_resources));

	res_similarity.resize(base_network->max_resources);
	for (int i = 0; i < base_network->max_resources; i++) {
		res_similarity[i].resize(base_network->max_resources);
	}

	//display_network(base_network, 0);
	//display_resources(base_network);

	exploit_cost = (int*) calloc(sizeof(int), (base_network->max_resources));

	net_p extended_network = new net_t;

	copy_network(base_network, extended_network);
	network_mangling(extended_network);

	//display_network(extended_network, 0);

	net_p evolved_network = new net_t;

	copy_network(extended_network, evolved_network);

	chromosome *attackers = (chromosome *)malloc(sizeof(chromosome) * pop_size_attack);
	chromosome *defenders = (chromosome *)malloc(sizeof(chromosome) * pop_size_defense);

	// create lists of visited nodes for each attacker
	vector< vector<int> > visited(pop_size_attack);
	for(int i = 0; i < pop_size_attack; i++)		
		visited[i].resize(evolved_network->max_network);

	//Assign attacker to a node in the network
	if (attacker_node == -1) {
		attacker_node = create_attacker_node(evolved_network);
	}

	//Main loop
	for (n = 0; n < runs; n++) {

		get_resource_similarity(res_similarity, base_network->max_resources);
		display_resource_similarity(res_similarity, base_network->max_resources);
		get_resource_popularity(resource_popularity, base_network->max_resources);
		get_vulnerability_cost(exploit_cost, base_network->max_resources, attack_budget);

		network_stats(evolved_network, res_similarity, exploit_cost);

		printf("Run %d...\n", n + 1);
		sprintf(name, "log_%d.txt", n + 1);
		for (i = 0; i < generations; i++) {
			printf("\b\b\b\b\b\b\b\b\bgen: %d", i + 1);
			if (i == 0) {
				initialize(attackers, pop_size_attack, genotype_size_attacker, attack_budget);
				initialize(defenders, pop_size_defense, genotype_size_defender, defense_budget);

				for (uint j = 0; j < pop_size_defense; j++) {
					defenders[j].fitness = run_defense_move(evolved_network, visited[0], defenders, j, res_similarity);
					for (uint z = 0; z < pop_size_attack; z++) {
						attackers[z].fitness += run_attack_move(evolved_network, attackers, z, res_similarity, exploit_cost, visited[z], i, n, -1);
					}				
				}
			}

			// select the best attacker and defender
			int best_attacker = 0, best_defender = 0;
			for(uint i = 1; i < pop_size_defense; i++)
				if(defenders[i].fitness > defenders[best_defender].fitness)
					best_defender = i;
			for(uint i = 1; i < pop_size_attack; i++)
				if(attackers[i].fitness > attackers[best_attacker].fitness)
					best_attacker = i;

			//static defender, active attacker
			if (scenario == 1) {
				selection(attackers, pop_size_attack, genotype_size_attacker, attacker_objective);
				mutation(attackers, pop_size_attack, ind_mut_prob_attack, genotype_size_attacker);

				set_fitness_to_zero(attackers, pop_size_attack);
				set_fitness_to_zero(defenders, pop_size_defense);

				for (uint z = 0; z < pop_size_attack; z++) {
					for (uint k = 0; k < games; k++) {
						defenders[best_defender].fitness += run_defense_move(evolved_network, visited[z], defenders, best_defender, res_similarity);
						attackers[z].fitness += run_attack_move(evolved_network, attackers, z, res_similarity, exploit_cost, visited[z], i, n, k);
						restore_budget(defenders, pop_size_defense, defense_budget, best_defender);
						restore_budget(attackers, pop_size_attack, attack_budget, z);

						// update adjacency changes before the next round
						evolved_network->last_adjacency = evolved_network->adjacency;
					}
				}

				// reset lists of visited nodes
				for (int k = 0; k < pop_size_attack; k++) {
					visited[k].assign(evolved_network->max_network, 0);
				}
			}

			//active defender, static attacker
			else if (scenario == 2) {
				selection(defenders, pop_size_defense, genotype_size_defender, defender_objective);
				mutation(defenders, pop_size_defense, ind_mut_prob_defense, genotype_size_defender);

				set_fitness_to_zero(attackers, pop_size_attack);
				set_fitness_to_zero(defenders, pop_size_defense);

				for (uint j = 0; j < pop_size_defense; j++) {
					for (uint k = 0; k < games; k++) {
						defenders[j].fitness += run_defense_move(evolved_network, visited[best_attacker], defenders, j, res_similarity);
						attackers[best_attacker].fitness += run_attack_move(evolved_network, attackers, best_attacker, res_similarity, exploit_cost, visited[best_attacker], i, n, k);
						restore_budget(defenders, pop_size_defense, defense_budget, j);
						restore_budget(attackers, pop_size_attack, attack_budget, best_attacker);

						// update adjacency changes before the next round
						evolved_network->last_adjacency = evolved_network->adjacency;
					}

					// reset lists of visited nodes
					for (int k = 0; k < pop_size_attack; k++) {
						visited[k].assign(evolved_network->max_network, 0);
					}
				}
			}

			//active defender, active attacker
			else {
				selection(defenders, pop_size_defense, genotype_size_defender, defender_objective);
				mutation(defenders, pop_size_defense, ind_mut_prob_defense, genotype_size_defender);
				selection(attackers, pop_size_attack, genotype_size_attacker, attacker_objective);
				mutation(attackers, pop_size_attack, ind_mut_prob_attack, genotype_size_attacker);
			
				set_fitness_to_zero(attackers, pop_size_attack);
				set_fitness_to_zero(defenders, pop_size_defense);

				for (uint j = 0; j < pop_size_defense; j++) {
					for (uint z = 0; z < pop_size_attack; z++) {
						for (uint k = 0; k < games; k++) {
							defenders[j].fitness += run_defense_move(evolved_network, visited[z], defenders, j, res_similarity);
							attackers[z].fitness += run_attack_move(evolved_network, attackers, z, res_similarity, exploit_cost, visited[z], i, n, k);
							restore_budget(defenders, pop_size_defense, defense_budget, j);
							restore_budget(attackers, pop_size_attack, attack_budget, z);

							// update adjacency changes before the next round
							evolved_network->last_adjacency = evolved_network->adjacency;
						}
					}

					// reset lists of visited nodes
					for (int k = 0; k < pop_size_attack; k++) {
						visited[k].assign(evolved_network->max_network, 0);
					}
				}
			}

			logging(name, log_level, i + 1, defenders, pop_size_defense, "Defense");
			logging(name, log_level, i + 1, attackers, pop_size_attack, "Attack");

			restore_budget(defenders, pop_size_defense, defense_budget, -1);
			restore_budget(attackers, pop_size_attack, attack_budget, -1);

			copy_network(extended_network, evolved_network);
			network_mangling(evolved_network);
		} //loop for generations

		printf("\n");
		
		final_stats(final_output_file, n + 1, defenders, pop_size_defense, attackers, pop_size_attack, generations);
		
	} //loop for runs

	/*free(visited_all);
	delete_network(base_network);
	delete_network(extended_network);
	delete_network(evolved_network);
	delete_population(attackers, pop_size_attack, genotype_size_attacker);
	delete_population(defenders, pop_size_defense, genotype_size_defender);*/
}