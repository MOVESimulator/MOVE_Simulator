#include "defender.h"
#include "helper.h"
#include <math.h>


double run_defense_move(net_p network, vector<int>& visited_nodes, chromosome defenders[], int individual, vector< vector<double> >& similarity)
{
	int add = 0;
	int added_path = 0, added_host = 0, added_resource = 0;
	int remove = 0;
	int removed_path = 0, removed_host = 0, removed_resource = 0;
	double values_pre[3] = { 0.0, 0.0, 0.0 }, values_post[3] = { 0.0, 0.0, 0.0 };
	int total_spent = 0;
	int temp = 0, count = 0;

	// decode add and remove affinity and scale if necessary
	add = (int)(((double)defenders[individual].genes[0] / 100) * (1 + defenders[individual].budget));
	remove = (int)(((double)defenders[individual].genes[4] / 100) * (1 + defenders[individual].budget));

	// scale to budget
	int action_sum = add + remove;
	if(action_sum > defenders[individual].budget) {
		double ratio = 1. * defenders[individual].budget / action_sum;
		add = (int)(0.5 + 1. * add * ratio);
		remove = (int)(0.5 + 1. * remove * ratio);
	}

	// calculate specific action percentages
	int add_sum = defenders[individual].genes[1] + defenders[individual].genes[2] + defenders[individual].genes[3];
	added_path = (int)(((double)defenders[individual].genes[1] / add_sum) * (1 + add));
	added_host = (int)(((double)defenders[individual].genes[2] / add_sum) * (1 + add));
	added_resource = (int)(((double)defenders[individual].genes[3] / add_sum) * (1 + add));

	// scale to full alloted budget
	if((added_path + added_host + added_resource) < add) {
		int which = get_random_int(0, 2);
		while((added_path + added_host + added_resource) < add) {
			switch(which) {
				case 0: added_path++; break;
				case 1: added_host++; break;
				case 2: added_resource++; break;
			}
			which = (which++) % 3;
		}
	}

	int remove_sum = defenders[individual].genes[5] + defenders[individual].genes[6] + defenders[individual].genes[7];
	removed_path = (int)(((double)defenders[individual].genes[5] / remove_sum) * (1 + remove));
	removed_host = (int)(((double)defenders[individual].genes[6] / remove_sum) * (1 + remove));
	removed_resource = (int)(((double)defenders[individual].genes[7] / remove_sum) * (1 + remove));

	// scale to full alloted budget
	if((removed_path + removed_host + removed_resource) < remove) {
		int which = get_random_int(0, 2);
		while((removed_path + removed_host + removed_resource) < remove) {
			switch(which) {
				case 0: removed_path++; break;
				case 1: removed_host++; break;
				case 2: removed_resource++; break;
			}
			which = (which++) % 3;
		}
	}

	if (added_path < 0 || added_host < 0 || added_resource < 0 || removed_path < 0 || removed_host < 0 || removed_resource < 0) {
		puts("Error in defense budget\n");
	}

	network_spatial_spread(network, similarity, values_pre);

	int vertices_limit = network->num_vertices;

	// attack detection: check non real_nodes, compare to visited_nodes, throw dice
	vector<short> detected(network->max_network, 0);
	network->num_detected = 0;
	for(int i = 0; i < network->num_vertices; i++) {
		if(visited_nodes[i] == 1 && get_random_double() > 0.5 && 
			((i >= network->core_vertices) || (i < network->core_vertices && network->real_nodes[i] != 1))) {
				detected[i] = 1;
				network->num_detected++;
		}
	}
	network->detected_attacks = detected;

	count = 0;
	temp = added_host;
	while (temp > 0 && network->num_vertices < (vertices_limit + (int) max_honeypots) && count != (network->num_vertices * network->num_vertices)) {//add host
		total_spent += add_host(network);
		temp--;
		count++;
	}

	temp = added_path;
	count = 0;
	while (temp > 0 && count != (network->num_vertices * network->num_vertices)) { //add path
		total_spent += add_path(network);
		temp--;
		count++;
	}

	temp = added_resource;
	count = 0;
	while (temp > 0 && count != (network->num_vertices * network->num_vertices)) { //add resource
		total_spent += add_resource(network, -1);
		temp--;
		count++;
	}

	temp = removed_path;
	count = 0;
	while (temp > 0 && count != (network->num_vertices * network->num_vertices)) { //remove path
		total_spent += delete_path(network);
		temp--;
		count++;
	}

	temp = removed_host;
	count = 0;
	while (temp > 0 && (network->core_vertices < network->num_vertices) && count != (network->num_vertices * network->num_vertices)) { //remove host
		total_spent += delete_host(network);
		temp--;
		count++;
	}

	temp = removed_resource;
	count = 0;
	while (temp > 0 && count != (network->num_vertices * network->num_vertices)) { //remove resource
		total_spent += delete_resource(network, -1);
		temp--;
		count++;
	}

	network_spatial_spread(network, similarity, values_post);

	return (double)fabs((values_post[0] - values_pre[0]) + (values_post[1] - values_pre[1]) + (values_post[2] - values_pre[2]));
}


int find_attacker(net_p network, int* visited)
{
	int count = 0;
	int i = 0;
	int honeypots_visited = 0;

	while (visited[i] != 0) {
		count++;
	}

	for (i = network->core_vertices - 1; i < network->num_vertices; i++) {
		for (int j = 0; j < count; j++) {
			if (visited[j] == i) {
				honeypots_visited++;
			}
		}
	}
	return honeypots_visited;
}
