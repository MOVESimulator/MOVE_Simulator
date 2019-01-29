#include "attacker.h"
#include <iostream>
#include <algorithm>

// genotype key
const int SCAN = 0;
const int SCAN_HORIZONTAL = 1;
const int SCAN_VERTICAL = 2;
const int EXPLOIT_SCAN = 3;
const int EXPLOIT_NOSCAN = 4;
const int EXPLOIT_NOSCAN_MAX = 5;
const int EXPLOIT_NOSCAN_DIV = 6;


// find all connected nodes
void get_accessible_nodes(net_p network, vector<int>& accessible, int current_node)
{
	for(int node = 0; node < network->num_vertices; node++) {
		if(node == current_node || network->adjacency[current_node][node] != 1 || accessible[node] == 1)
			continue;
		accessible[node] = 1;
		// check if firewall
		if(is_firewall(network, node))
			continue;
		get_accessible_nodes(network, accessible, node);
	}
}


double run_attack_move(net_p network, chromosome attackers[], int individual, vector< vector<double> >& similarity, int *exploit_cost, int generation, int run, int current_game)
{
	int wait = 0;
	double scan = 0;
	double scan_horizontal = 0;
	double scan_vertical = 0;
	double exploit_after_scan = 0;
	double exploit_without_scan = 0;
	double exploit_without_scan_diversify = 0;
	double exploit_without_scan_maximize = 0;
	double total, scan_total, exploit_total;
	int position = 0;
	int spent = 0;
	int cost_of_exploit = 0;
	double fitness_exploit = 0.0;
	int exploited = 0;

	int budget = attackers[individual].budget;

	vector<int> resource_occurence(network->max_resources);
	vector<int> neighbors(network->num_vertices, 0);
	vector<int> volatile_neighbors(network->num_vertices, 0);

	// check current neighborhood
	find_neighborhood(network, neighbors);

	// compare to last neighborhood, mark volatile neighborhood nodes
	for(uint i = 0; i < neighbors.size(); i++)
		if(neighbors[i] != network->last_adjacency[attacker_node][i])
			volatile_neighbors[i] = 1;

	// divide between scan, exploit_after_scan, exploit_without_scan
	scan = attackers[individual].genes[SCAN] / 100.;
	exploit_after_scan = attackers[individual].genes[EXPLOIT_SCAN] / 100.;
	exploit_without_scan = attackers[individual].genes[EXPLOIT_NOSCAN] / 100.;
	total = scan + exploit_after_scan + exploit_without_scan;

	scan_horizontal = attackers[individual].genes[SCAN_HORIZONTAL] / 100.;
	scan_vertical = attackers[individual].genes[SCAN_VERTICAL] / 100.;
	scan_total = scan_horizontal + scan_vertical;

	exploit_without_scan_diversify = attackers[individual].genes[EXPLOIT_NOSCAN_MAX] / 100.;
	exploit_without_scan_maximize = attackers[individual].genes[EXPLOIT_NOSCAN_DIV] / 100.;
	exploit_total = exploit_without_scan_diversify + exploit_without_scan_maximize;

	// get all accessible nodes
	vector<int> accessible(network->num_vertices, 0);
	get_accessible_nodes(network, accessible, attacker_node);

	// perform actions until budget depleted
	int remaining_budget = budget;
	while(remaining_budget > 0) {

		// choose action
		int action;
		double rnd = total * get_random_double();
		if(rnd < scan)
			action = SCAN;
		else if(rnd < (scan + exploit_after_scan))
			action = EXPLOIT_SCAN;
		else
			action = EXPLOIT_NOSCAN;

		// choose subaction
		if(action == SCAN) {
			rnd = scan_total * get_random_double();
			if(rnd < scan_horizontal)
				action = SCAN_HORIZONTAL;
			else
				action = SCAN_VERTICAL;
		}
		if(action == EXPLOIT_NOSCAN) {
			rnd = exploit_total * get_random_double();
			if(rnd < exploit_without_scan_diversify)
				action = EXPLOIT_NOSCAN_DIV;
			else
				action = EXPLOIT_NOSCAN_MAX;
		}

		//cout << action << endl;

		// perform action (up to remaining budget)

		// scan a random port on all accessible hosts
		if(action == SCAN_HORIZONTAL) {
			int port = get_random_int(0, num_ports - 1);
			int current_node = 0;
			for(int node = 0; node < network->num_vertices; node++) {
				if(node == attacker_node || accessible[node] == 0)
					continue;
				// for scanning a single port, incur only access_cost
				remaining_budget -= access_cost;
				if(remaining_budget < 0)
					break;
				// check if there are resources on this port
				for(uint i = 0; i < network->nodes[node].resource.size(); i++) {
					int resource = network->nodes[node].resource[i];
					if(network->nodes[node].ports[port] == resource) {
						// mark scanned resources
						add_scanned_resource(network, node, resource);
						network->nodes[node].scanned = true;
					}
				}
			}
		}

		// scan all ports on a random accessible host
		if(action == SCAN_VERTICAL) {
			remaining_budget -= access_cost;
			if(remaining_budget < 0)
				break;
			// find random accessible host
			int node = get_random_int(0, network->num_vertices - 1), counter = 0;
			while((counter++) < network->num_vertices && accessible[node] != 1 && node != attacker_node)
				node = (node + 1) % network->num_vertices;
			// scan all ports 
			for(uint port = 0; port < num_ports - 1; port++) {
				// for scanning a port, incur port_scan_cost
				remaining_budget -= port_scan_cost;
				if(remaining_budget < 0)
					break;
				// check if there are resources on this port
				for(uint i = 0; i < network->nodes[node].resource.size(); i++) {
					int resource = network->nodes[node].resource[i];
					if(network->nodes[node].ports[port] == resource) {
						// mark scanned resources
						add_scanned_resource(network, node, resource);
						network->nodes[node].scanned = true;
					}
				}
			}
		}

		// exploit a random scanned resource on a random scanned host
		if(action == EXPLOIT_SCAN) {
			// find random scanned node
			int node = get_random_int(0, network->num_vertices - 1), counter = 0;
			while((counter++) < network->num_vertices && (network->nodes[node].scanned != true || node == attacker_node))
				node = (node + 1) % network->num_vertices;
			if(network->nodes[node].scanned != true)
				break;

			// find random scanned resource
			int resource = network->nodes[node].scanned_resources[get_random_int(0, network->nodes[node].scanned_resources.size() - 1)];

			// check exploit cost
			remaining_budget -= exploit_cost[resource];
			if(remaining_budget < 0)
				break;

			// roll dice
			if(get_random_double() > 0.5)
				continue;

			// mark node as exploited
			if(network->nodes[node].exploited == false) {
				network->num_exploited++;
				exploited++;
			}
			network->nodes[node].exploited = true;

			// if node was a firewall, mark inactive
			if(is_firewall(network, node))
				firewall_exploited(network, node);
		}

		// try to exploit the most popular resource on a random node (maximize)
		if(action == EXPLOIT_NOSCAN_MAX) {
			// choose the most popular resource
			int cost_of_exploit = exploit_cost[resource_popularity[0]];
			int resource = resource_popularity[0];

			// find random accessible host
			int node = get_random_int(0, network->num_vertices - 1), counter = 0;
			while((counter++) < network->num_vertices && accessible[node] != 1 && node != attacker_node)
				node = (node + 1) % network->num_vertices;

			// for all ports 
			for(uint port = 0; port < num_ports; port++) {
				// incur exploit cost
				remaining_budget -= cost_of_exploit;
				if(remaining_budget < 0)
					break;
				// check resource on this port
				if(network->nodes[node].ports[port] == resource) {
					// roll dice
					if(get_random_double() > 0.3)
						continue;

					// mark node as exploited
					if(network->nodes[node].exploited == false) {
						network->num_exploited++;
						exploited++;
					}
					network->nodes[node].exploited = true;

					// if node was a firewall, mark inactive
					if(is_firewall(network, node))
						firewall_exploited(network, node);
				}
			}
		}

		// try to exploit a random resource on a random node (diversify)
		if(action == EXPLOIT_NOSCAN_DIV) {
			// choose a random resource
			int resource = get_random_int(1, network->max_resources);
			int cost_of_exploit = exploit_cost[resource];

			// find random accessible host
			int node = get_random_int(0, network->num_vertices - 1), counter = 0;
			while((counter++) < network->num_vertices && accessible[node] != 1 && node != attacker_node)
				node = (node + 1) % network->num_vertices;

			// for all ports 
			for(uint port = 0; port < num_ports - 1; port++) {
				// incur exploit cost
				remaining_budget -= cost_of_exploit;
				if(remaining_budget < 0)
					break;
				// check resource on this port
				if(network->nodes[node].ports[port] == resource) {
					// roll dice
					if(get_random_double() > 0.3)
						continue;

					// mark node as exploited
					if(network->nodes[node].exploited == false) {
						network->num_exploited++;
						exploited++;
					}
					network->nodes[node].exploited = true;

					// if node was a firewall, mark inactive
					if(is_firewall(network, node))
						firewall_exploited(network, node);
				}
			}
		}

	}

	return exploited;
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