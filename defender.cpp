#include "defender.h"
#include "helper.h"
#include <math.h>
#include <iostream>


// genotype key
const int ADD = 0;
const int ADD_PATH = 1;
const int ADD_HOST = 2;
const int ADD_RESOURCE = 3;
const int REMOVE = 4;
const int REMOVE_PATH = 5;
const int REMOVE_HOST = 6;
const int REMOVE_RESOURCE = 7;
const int MOVE_PORT = 8;


double run_defense_move(net_p network, chromosome defenders[], int individual, vector< vector<double> >& similarity)
{
	//cout << "def:begin" << endl;

	double add = 0;
	double add_path_ = 0, add_host_ = 0, add_resource_ = 0;
	double remove = 0;
	double remove_path_ = 0, remove_host_ = 0, remove_resource_ = 0, move_port_ = 0;
	double total, total_add, total_remove;
	double values_pre[3] = { 0.0, 0.0, 0.0 }, values_post[3] = { 0.0, 0.0, 0.0 };
	int total_spent = 0;
	int temp = 0, count = 0;

	int budget = defenders[individual].budget;

	// divide between actions
	add = defenders[individual].genes[ADD] / 100.;
	add_path_ = defenders[individual].genes[ADD_PATH] / 100.;
	add_host_ = defenders[individual].genes[ADD_HOST] / 100.;
	add_resource_ = defenders[individual].genes[ADD_RESOURCE] / 100.;
	total_add = add_path_ + add_host_ + add_resource_;

	remove = defenders[individual].genes[REMOVE] / 100.;
	remove_path_ = defenders[individual].genes[REMOVE_PATH] / 100.;
	remove_host_ = defenders[individual].genes[REMOVE_HOST] / 100.;
	remove_resource_ = defenders[individual].genes[REMOVE_RESOURCE] / 100.;
	move_port_ = defenders[individual].genes[MOVE_PORT] / 100.;
	total_remove = remove_path_ + remove_host_ + remove_resource_ + move_port_;

	total = add + remove;

	network_spatial_spread(network, similarity, values_pre);


	// perform actions until budget depleted
	int remaining_budget = budget;
	while(remaining_budget > 0) {

		remaining_budget -= defense_cost;
		if(remaining_budget < 0)
			break;

		// choose action
		int action;
		double rnd = total * get_random_double();
		if(rnd < add)
			action = ADD;
		else
			action = REMOVE;

		// choose subaction
		if(action == ADD) {
			rnd = total_add * get_random_double();
			if(rnd < add_path_)
				action = ADD_PATH;
			else if(rnd < (add_path_ + add_host_))
				action = ADD_HOST;
			else
				action = ADD_RESOURCE;
		}
		if(action == REMOVE) {
			rnd = total_remove * get_random_double();
			if(rnd < remove_path_)
				action = REMOVE_PATH;
			else if(rnd < remove_path_ + remove_host_)
				action = REMOVE_HOST;
			else if(rnd < remove_path_ + remove_host_ + remove_resource_)
				action = REMOVE_RESOURCE;
			else
				action = MOVE_PORT;
		}

		//cout << action << endl;

		// TODO: attack detection: check exploited nodes

		switch(action) {
		case ADD_PATH: 
			add_host(network);
			break;
		case ADD_HOST: 
			add_path(network);
			break;
		case ADD_RESOURCE: 
			add_resource(network, -1);
			break;
		case REMOVE_PATH: 
			delete_path(network);
			break;
		case REMOVE_HOST: 
			delete_host(network);
			break;
		case REMOVE_RESOURCE: 
			delete_resource(network, -1);
			break;
		case MOVE_PORT: 
			move_port(network, -1);
			break;
		}
	}


	network_spatial_spread(network, similarity, values_post);

	//cout << "def:end" << endl;

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
