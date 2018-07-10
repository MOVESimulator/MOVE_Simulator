#include "attacker.h"


double run_attack_move(net_p network, chromosome attackers[], int individual, vector< vector<double> >& similarity, int *exploit, vector<int>& scanned_nodes, int generation, int run, int current_game)
{
	int wait = 0;
	int scan = 0;
	int scan_bfs = 0;
	int scan_dfs = 0;
	int exploit_after_scan = 0;
	int exploit_without_scan = 0;
	int exploit_without_scan_diversify = 0;
	int exploit_without_scan_maximize = 0;
	int max = 0;
	int position = 0;
	int spent = 0;
	int cost_of_exploit = 0;
	double fitness_exploit = 0.0;

	vector<int> visited_bfs(network->num_vertices);
	vector<int> visited_dfs(network->num_vertices);
	vector<int> resource_occurence(network->max_resources);
	vector<int> neighbors(network->num_vertices, 0);
	vector<int> volatile_neighbors(network->num_vertices, 0);

	// check current neighborhood
	find_neighborhood(network, neighbors);

	// compare to last neighborhood, mark volatile neighborhood nodes
	for(uint i = 0; i < neighbors.size(); i++)
		if(neighbors[i] != network->last_adjacency[attacker_node][i])
			volatile_neighbors[i] = 1;

	// decode number of initial games to wait
	wait = (int)(((double)attackers[individual].genes[0] * games / 100));
	if(wait > current_game)
		return 0;

	// divide between scan, exploit_after_scan, exploit_without_scan
	scan = (int)(((double)attackers[individual].genes[1] / 100) * (1 + attackers[individual].budget));
	exploit_after_scan = (int)(((double)attackers[individual].genes[4] / 100) * (1 + attackers[individual].budget));
	exploit_without_scan = (int)(((double)attackers[individual].genes[5] / 100) * (1 + attackers[individual].budget));

	// if larger, scale within budget
	int actionSum = scan + exploit_after_scan + exploit_without_scan;
	if(actionSum > attackers[individual].budget) {
		double ratio = 1. * attackers[individual].budget / actionSum;
		scan = (int)(0.5 + 1. * scan * ratio);
		exploit_after_scan = (int)(0.5 + 1. * exploit_after_scan * ratio);
		exploit_without_scan = (int)(0.5 + 1. * exploit_without_scan * ratio);
	}

	if((scan + exploit_after_scan + exploit_without_scan) > attackers[individual].budget) {
		int which = get_random_int(0, 2);
		while((scan + exploit_after_scan + exploit_without_scan) > attackers[individual].budget) {
			switch(which) {
				case 0: if(scan > 0) scan--; break;
				case 1: if(exploit_after_scan > 0) exploit_after_scan--; break;
				case 2: if(exploit_without_scan > 0) exploit_without_scan--; break;
			}
			which = (which++) % 3;
		}
	}

	// calculate number of scan actions
	int scanSum = attackers[individual].genes[2] + attackers[individual].genes[3];
	scan_bfs = (int)(((double)attackers[individual].genes[2] / scanSum) * (scan));
	scan_dfs = (int)(((double)attackers[individual].genes[3] / scanSum) * (scan));

	// scale to full alloted budget
	if((scan_bfs + scan_dfs) < scan) {
		int which = get_random_int(0, 1);
		while((scan_bfs + scan_dfs) < scan) {
			switch(which) {
				case 0: scan_bfs++; break;
				case 1: scan_dfs++; break;
			}
			which = (which++) % 2;
		}
	}

	// calculate number of exploit without scan actions 
	int exploitSum = attackers[individual].genes[6] + attackers[individual].genes[7];
	exploit_without_scan_diversify = (int)(((double)attackers[individual].genes[6] / exploitSum) * (1 + exploit_without_scan));
	exploit_without_scan_maximize = (int)(((double)attackers[individual].genes[7] / exploitSum) * (1 + exploit_without_scan));

	// scale to full alloted budget
	if((exploit_without_scan_diversify + exploit_without_scan_maximize) < exploit_without_scan) {
		int which = get_random_int(0, 1);
		while((exploit_without_scan_diversify + exploit_without_scan_maximize) < exploit_without_scan) {
			switch(which) {
				case 0: exploit_without_scan_diversify++; break;
				case 1: exploit_without_scan_maximize++; break;
			}
			which = (which++) % 2;
		}
	}


	if (current_game >= wait && current_game != -1) {

		BFS(network, attacker_node, scan_bfs, &visited_bfs[0]);
		DFS(network, attacker_node, scan_dfs, &visited_dfs[0]);

		for (int i = 0; i < network->num_vertices; i++) {
			if (visited_bfs[i] == 1 || visited_dfs[i] == 1) {
				scanned_nodes[i] = 1;
			}
		}

		int count = 0;
		cost_of_exploit = exploit_cost[resource_popularity[0]];
		int random_node = get_random_int(0, network->num_vertices - 1);
		for (int j = 0; j < network->num_vertices && exploit_without_scan_maximize > 0; j++) { //exploit the vulnerability that occurs the most often
			int current_node = (random_node + j) % network->num_vertices;
			// skip changed nodes
			if(volatile_neighbors[random_node] == 1)
				continue;
			if (neighbors[current_node] == 1 && ((exploit_without_scan_maximize - cost_of_exploit * count) >= cost_of_exploit)) { //node is adjacent so attack is possible
				for (int z = 0; z < network->max_resource_per_host; z++) {
					if (network->resource[current_node][z] > 0) {
						count++;
						if (network->resource[current_node][z] == resource_popularity[0]) {
							fitness_exploit += cost_of_exploit;
						}
					}
				}
			}
		}

		int flag_diversify = 1;
		exploit_without_scan_diversify += (exploit_without_scan_maximize - cost_of_exploit * count); //use what remained

		random_node = get_random_int(0, network->num_vertices - 1);
		for (int j = 0; j < network->num_vertices && exploit_without_scan_diversify > 0; j++) { //exploit diversify
			int current_node = (random_node + j) % network->num_vertices;
			// skip changed nodes
			if(volatile_neighbors[random_node] == 1)
				continue;
			if (neighbors[current_node] == 1 && exploit_without_scan_diversify > spent) { //node is adjacent so attack is possible
				for (uint k = 0; k < diversify_resource; k++) {
					cost_of_exploit = exploit_cost[resource_popularity[k]];
					for (int z = 0; z < network->max_resource_per_host; z++) {
						if (network->resource[current_node][z] > 0 && flag_diversify) {
							spent = spent + cost_of_exploit;
							if (network->resource[current_node][z] == resource_popularity[k]) {
								fitness_exploit += cost_of_exploit;
								flag_diversify = 0;
								break;
							}
						}
					}
				}
				flag_diversify = 1;
			}
		}

		//exploit after scan
		for (int i = 0; i < network->num_vertices; i++) {
			if (scanned_nodes[i] == 1) {
				for (int z = 0; z < network->max_resource_per_host; z++) {
					if (network->resource[i][z] > 0) {
						resource_occurence[network->resource[i][z] - 1]++;
					}
				}
			}
		}

		for (int i = 0; i < network->max_resources; i++) {
			if (resource_occurence[i] > max) {
				max = resource_occurence[i];
				position = i;
			}
		}

		cost_of_exploit = exploit_cost[position];
		while (exploit_after_scan > 0) {
			random_node = get_random_int(0, network->num_vertices - 1);
			for (int j = 0; j < network->num_vertices && exploit_after_scan > 0; j++) {
				int current_node = (random_node + j) % network->num_vertices;
				// skip changed nodes
				if(volatile_neighbors[random_node] == 1)
					continue;
				if (scanned_nodes[current_node] == 1) { //node is visited so attack is possible
					for (int z = 0; z < network->max_resource_per_host; z++) {
						if (network->resource[current_node][z] > 0) { //there exist a resource
							if (network->resource[current_node][z] == position && (exploit_after_scan >= cost_of_exploit)) {
								fitness_exploit += cost_of_exploit;
								exploit_after_scan = exploit_after_scan - cost_of_exploit;
							}
							else {
								if (get_random_double() > (1 - similarity[position][network->resource[current_node][z]-1]) && (exploit_after_scan >= cost_of_exploit)) {
									fitness_exploit += cost_of_exploit;
									exploit_after_scan = exploit_after_scan - cost_of_exploit;
								}
								else {
									exploit_after_scan = exploit_after_scan - 1;
								}
							}
						}
					}
				}
			}
		}
	}
	else {
		fitness_exploit = 0;
	}

	//free(visited_bfs);
	//free(visited_dfs);
	//free(neighbors);
	//free(vulnerability_occurence);
	return fitness_exploit;
}


void find_neighborhood(net_p network, vector<int>& neighbors)
{
	for (int i = 0; i < network->num_vertices; i++) {
		if (network->adjacency[attacker_node][i] == 1) {
			neighbors[i] = 1;
		}
	}
}


int create_attacker_node(net_p network)
{
	return get_random_int(0, network->num_vertices);
}