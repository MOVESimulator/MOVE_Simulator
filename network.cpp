#include "main.h"
#include "helper.h"
#include "network.h"
#include <algorithm>

// delete network
void delete_network(net_p network) {
	free(network);
}

// create initial network with paths
net_p create_network(network_type type, int num_vertices, int max_network_size,
		double network_sparsity, int num_ports, int preconfig) {
	net_p network = new net_t;
	network->type = type;
	network->core_vertices = num_vertices;
	network->num_vertices = num_vertices;
	network->max_network = max_network_size;
	network->network_sparsity = network_sparsity;
	network->num_ports = num_ports;

	network->num_exploited = 0;

	network->adjacency.resize(network->max_network);
	for (int i = 0; i < network->max_network; i++) {
		network->adjacency[i].resize(network->max_network);
	}

	network->nodes.assign(network->core_vertices, Node(num_ports));

	network->detected_attacks.resize(network->max_network);

	if (preconfig == 1) {
		FILE *fout;
		int temp = 0;
		if ((fout = fopen(pre_adj, "r")) == NULL) {
			puts("Error reading preconfigured adjacency matrix\n");
			exit(0);
		}
		for (int i = 0; i < network->max_network; i++) {
			for (int j = 0; j < network->max_network; j++) {
				network->adjacency[i][j] = 0;
			}
		}
		for (int i = 0; i < network->num_vertices; i++) {
			for (int j = 0; j < network->num_vertices; j++) {
				fscanf(fout, "%d", &temp);
				network->adjacency[i][j] = temp;
			}
		}
		fclose(fout);
	} else {
		int node = 0;
		// mark all core vertices as real nodes
		for (uint i = 0; i < network->nodes.size(); i++)
			network->nodes[i].real_node = true;

		if (type == UNDIRECTED) {
			for (int i = 0; i < network->max_network; i++) {
				for (int j = 0; j < network->max_network; j++) {
					network->adjacency[i][j] = 0;
				}
			}
			for (int i = 0; i < network->num_vertices; i++) {
				for (int j = 0; j < network->num_vertices; j++) {
					if (network->adjacency[i][j] == 0 && i != j) {
						if (get_random_double() > network->network_sparsity) {
							network->adjacency[i][j] = 1;
							network->adjacency[j][i] = 1;
						}
					}
				}
			}
			int has_connection = 0;
			for (int i = 0; i < network->core_vertices; i++) {
				for (int j = 0; j < network->num_vertices; j++) {
					if (network->adjacency[i][j] == 1) {
						has_connection = 1;
					}
				}
				if (has_connection == 0) {
					node = get_random_int(0, network->num_vertices - 1);
					while (node == i) {
						node = get_random_int(0, network->num_vertices - 1);
					}
					network->adjacency[i][node] = 1;
					network->adjacency[node][i] = 1;
				}
				has_connection = 0;
			}
		} else { //for DIRECTED network
			for (int i = 0; i < network->num_vertices; i++) {
				for (int j = 0; j < network->num_vertices; j++) {
					if (network->adjacency[i][j] == 0 && i != j) {
						if (get_random_double() > network->network_sparsity) {
							network->adjacency[i][j] = 1;
						}
					}
				}
			}
			int has_connection = 0;
			for (int i = 0; i < network->core_vertices; i++) {
				for (int j = 0; j < network->num_vertices; j++) {
					if (network->adjacency[i][j] == 1) {
						has_connection = 1;
					}
				}
				if (has_connection == 0) {
					node = get_random_int(0, network->num_vertices - 1);
					while (node == i) {
						node = get_random_int(0, network->num_vertices - 1);
					}
					network->adjacency[i][node] = 1;
				}
				has_connection = 0;
			}
		}
	}

	// add firewalls
	for (int i = 0; i < network->num_vertices; i++) {
		// only real nodes can be firewalls
		if ((network->nodes[i].real_node)
				&& (get_random_double() < percentage_of_firewalls)) {
			network->nodes[i].firewall = true;
		}
	}

	network->last_adjacency = network->adjacency;

	return network;
}

// create initial resources, 1 per host
void create_resources(net_p network, int resources, int max_resources_per_host,
		int preconfig) {
	network->max_resources = resources;
	network->max_resource_per_host = max_resources_per_host;

	// initialize node resources and ports
	for (int i = 0; i < network->num_vertices; i++) {
		network->nodes[i].ports.assign(network->num_ports, -1);
	}

	if (preconfig == 1) {
		FILE *fout;
		int temp = 0;
		if ((fout = fopen(pre_vul, "r")) == NULL) {
			puts("Error reading preconfigured resource/vulnerability matrix\n");
			exit(0);
		}
		for (int i = 0; i < network->num_vertices; i++) {
			for (int j = 0; j < network->max_resource_per_host; j++) {
				fscanf(fout, "%d", &temp);
				network->nodes[i].resource[j] = temp;
				// assign resource to a random port
				int port = get_random_int(0, network->num_ports - 1);
				network->nodes[i].ports[port] = temp;
			}
		}
		fclose(fout);
	} else {
		for (int i = 0; i < network->num_vertices; i++) {
			// assign random resource
			int resource = get_random_int(0, network->max_resources - 1);
			network->nodes[i].resource.push_back(resource);
			// assign resource to a random port
			int port = get_random_int(0, network->num_ports - 1);
			network->nodes[i].ports[port] = resource;
		}
	}
}

/**
 * Add a resource, if success return 1, else 0
 */
int add_resource(net_p network, int select_host) {
//	printf("addresource\n");
	int flag1 = 1;
	int flag2 = 1;
	int count = 0;
	int resource;
	int count2 = 0;
	int host;

	if (select_host == -1) {
		while (flag2) {
			host = get_random_int(0, network->num_vertices - 1);

			//// first affect on detected, then random
			//if(network->num_detected > 0) {
			//	while(network->detected_attacks[host] != 1)
			//		host = (host + 1) % network->num_vertices;
			//	// reset selected
			//	network->detected_attacks[host] = 0;
			//	network->num_detected--;
			//}

			if (count_resources(network, host)
					< network->max_resource_per_host) {
				flag2 = 0;
			} else {
				count++;
			}
			if (count
					== (network->num_vertices * network->max_resource_per_host)) {
				return 0;
			}
		}
	} else {
		host = select_host;
	}

	int num_res_host = count_resources(network, host);
	// if already at max resources, return
	if (num_res_host == network->max_resource_per_host)
		return 0;

	// random resource
	resource = get_random_int(0, network->max_resources - 1);

	// check if the host already has that resource
	while (1) {
		uint i = 0;
		for (i = 0; i < network->nodes[host].resource.size(); i++) {
			if (resource == network->nodes[host].resource[i])
				break;
		}
		// no such resource, good to add
		if (i == network->nodes[host].resource.size())
			break;

		resource++;
		if (resource == (network->max_resources))
			resource = 0;
	}

	// add the resource
	network->nodes[host].resource.push_back(resource);
	// assign resource to a random port
	// choose random unused port
	int new_port = get_random_int(0, network->num_ports - 1);
	while (network->nodes[host].ports[new_port] > -1)
		new_port = (new_port + 1) % network->num_ports;
	network->nodes[host].ports[new_port] = resource;

	return 1;
}

// add a host and connect it with other hosts, if success return 1, else 0. If the network equals full size, first delete a node and then create a node. For that node create a resource
int add_host(net_p network) {
//	printf("addhost\n");
	int total = 0;
	if (network->num_vertices == network->max_network) {
		total = delete_host(network);
	}

	if (network->num_vertices == network->max_network) {
		return 0;
	}

	network->num_vertices++;
	if (type == UNDIRECTED) {
		for (int i = 0; i < network->num_vertices; i++) {
			if (get_random_double() >= network->network_sparsity
					|| (network->detected_attacks.size()
							== network->num_vertices
							&& network->detected_attacks[i] == 1)) {
				network->adjacency[network->num_vertices - 1][i] = 1;
				network->adjacency[i][network->num_vertices - 1] = 1;
			} else {
				network->adjacency[network->num_vertices - 1][i] = 0;
				network->adjacency[i][network->num_vertices - 1] = 0;
			}
		}
	} else {
		for (int i = 0; i < network->num_vertices; i++) {
			if (get_random_double() >= network->network_sparsity) {
				network->adjacency[network->num_vertices - 1][i] = 1;
			} else {
				network->adjacency[network->num_vertices - 1][i] = 0;
			}
		}
	}
	Node new_host(network->num_ports);
	network->nodes.push_back(new_host);
	total += add_resource(network, network->num_vertices - 1);

	if (total == 0)
		printf("add_host: greska!\n");

	return total;
}

// delete a host, return 1 if success, 0 otherwise. Core nodes cannot be deleted
int delete_host(net_p network) {
//	printf("deletehost\n");
	if (network->core_vertices < network->num_vertices) {
		// TODO: first choose detected, then random
		// smijemo: one za koje real_nodes[i] != 1
		if (network->num_detected > 0) {

		}

		int del = get_random_int(network->core_vertices,
				network->num_vertices - 1);

		// erase del-th element in data structures:
		// move to shrink
		for (int i = del; i < network->num_vertices - 1; i++) {
			network->adjacency[i] = network->adjacency[i + 1];
			network->last_adjacency[i] = network->last_adjacency[i + 1];
		}

		for (int i = 0; i < network->num_vertices; i++) {
			for (int j = del; j < network->num_vertices - 1; j++) {
				network->adjacency[i][j] = network->adjacency[i][j + 1];
				network->last_adjacency[i][j] =
						network->last_adjacency[i][j + 1];
			}
		}

		network->nodes.erase(network->nodes.begin() + del);

		// delete contents of the last one
		network->adjacency[network->num_vertices - 1].assign(
				network->max_network, 0);
		network->last_adjacency[network->num_vertices - 1].assign(
				network->max_network, 0);

		network->num_vertices--;

//		display_network(network, 0);
//		display_resources(network);

		return 1;
	} else {
		return 0;
	}
}

// function that adds a path, if success return 0, otherwise 1
int add_path(net_p network) {
//	printf("addpath\n");
	int flag = 1;
	int count = 0;
	while (flag) {
		// first choose detected, then random
		int source = get_random_int(0, network->num_vertices - 1);
		if (network->num_detected > 0) {
			while (network->detected_attacks[source] != 1)
				source = (source + 1) % network->num_vertices;
			// reset selected
			network->detected_attacks[source] = 0;
			network->num_detected--;
		}

		int destination = get_random_int(0, network->num_vertices - 1);

		while (source == destination) {
			destination = get_random_int(0, network->num_vertices - 1);
		}

		if (network->adjacency[source][destination] == 0) {
			if (type == UNDIRECTED) {
				network->adjacency[source][destination] = 1;
				network->adjacency[destination][source] = 1;
				flag = 0;
			} else {
				network->adjacency[source][destination] = 1;
				flag = 0;
			}
		} else {
			count++;
		}
		if (count == (network->num_vertices * network->num_vertices)
				&& flag == 1) {
			return 0;
		}
	}
	return 1;
}

// function to delete a path, on success return 1, else 0
int delete_path(net_p network) {
//	printf("deletepath\n");
	int flag = 1;
	int count = 0;
	while (flag) {
		if (count == (network->num_vertices * network->num_vertices)
				&& flag == 1) {
			return 0;
		}

		// first choose detected, then random
		int source = get_random_int(0, network->num_vertices - 1);
		if (network->num_detected > 0) {
			while (network->detected_attacks[source] != 1)
				source = (source + 1) % network->num_vertices;
			// reset selected
			network->detected_attacks[source] = 0;
			network->num_detected--;
		}

		int destination = get_random_int(0, network->num_vertices - 1);

		while (source == destination) {
			destination = get_random_int(0, network->num_vertices - 1);
		}

		// if either source or destination are in real_nodes, check connectivity
		if (source < network->core_vertices
				&& network->nodes[source].real_node == true) {
			int connections = 0;
			for (int i = 0; i < network->num_vertices && connections < 2; i++)
				connections += network->adjacency[source][i];
			if (connections < 2) {
				count++;
				continue;
			}
		}

		if (destination < network->core_vertices
				&& network->nodes[destination].real_node == true) {
			int connections = 0;
			for (int i = 0; i < network->num_vertices && connections < 2; i++)
				connections += network->adjacency[source][i];
			if (connections < 2) {
				count++;
				continue;
			}
		}

		if (network->adjacency[source][destination] == 1) {
			if (type == UNDIRECTED) {
				network->adjacency[source][destination] = 0;
				network->adjacency[destination][source] = 0;
				flag = 0;
			} else {
				network->adjacency[source][destination] = 0;
				flag = 0;
			}
		} else {
			count++;
		}

	}
	return 1;
}

//function that combines delete_path and add_path functionalities. Currently not used
void change_path(net_p network) {
	delete_path(network);
	add_path(network);
}

// count the number of resources for a specific host
int count_resources(net_p network, int host) {
	return network->nodes[host].resource.size();
}

/**
 * Function that deletes a single resource. If success return 1, else 0. 
 * If a host has only one resource, it is not deleted.
 */
int delete_resource(net_p network, int select_host) {
//	printf("deleteresource\n");
	int flag = 1;
	int temp = 0;
	int host;

	// select a random host on which a resource will be deleted
	if (select_host == -1) {
		host = get_random_int(0, network->num_vertices - 1);

		// select host with more than a single resource
		int offset = 0;
		while (count_resources(network, host) == 1
				&& offset < network->num_vertices)
			host = (host + (++offset)) % network->num_vertices;
		// no such hosts, fail
		if (offset == network->num_vertices)
			return 0;
	}

	// get number of resources on host
	int count = count_resources(network, host);
	if (count == 1)
		return 0;

	if (count == 0)
		count = 0;

	//// if there is a single resource on the selected real_nodes host, fail
	//if(host < network->core_vertices && network->real_nodes[host] == 1 && count == 1)
	//	return 0;

	// remove resource that is not the first one
	int resource_position;
	resource_position = get_random_int(1, count - 1);
	int deleted_resource = network->nodes[host].resource[resource_position];
	network->nodes[host].resource.erase(
			network->nodes[host].resource.begin() + resource_position);
	for (int port = 0; port < network->num_ports; port++)
		if (network->nodes[host].ports[port] == deleted_resource)
			network->nodes[host].ports[port] = -1;

	return 1;
}

int add_scanned_resource(net_p network, int node, int resource) {
	if (find(network->nodes[node].scanned_resources.begin(),
			network->nodes[node].scanned_resources.end(), resource)
			== network->nodes[node].scanned_resources.end()) {
		network->nodes[node].scanned_resources.push_back(resource);
		return 1;
	}
	return 0;
}

/**
 * Function that changes a port for a single resource. If success return 1, else 0. 
 */
int move_port(net_p network, int select_host) {
//	printf("deleteresource\n");
	int flag = 1;
	int temp = 0;
	int host;

	// select a random host 
	if (select_host == -1) {
		host = get_random_int(0, network->num_vertices - 1);
	}

	// choose random port
	int port = get_random_int(0, network->num_ports - 1);
	while (network->nodes[host].ports[port] < 0)
		port = (port + 1) % network->num_ports;

	// choose random unused port
	int new_port = get_random_int(0, network->num_ports - 1);
	while (network->nodes[host].ports[new_port] > -1)
		new_port = (new_port + 1) % network->num_ports;

	network->nodes[host].ports[new_port] = network->nodes[host].ports[port];
	network->nodes[host].ports[port] = -1;

	return 1;
}

//currently works only for undirected networks. Not working at all?? We do not use this function
int add_subnet(net_p network, int select_host) {
	int host;
	int flag = 1;
	int count_changes = 0;

	if (select_host == -1) {
		while (flag) {
			host = get_random_int(0, network->num_vertices - 1);
			if (count_paths(network, host) >= 2
					&& count_paths(network, host) < network->num_vertices - 1) {
				flag = 0;
			}
		}
	} else {
		host = select_host;
	}

	short *list = (short *) calloc(sizeof(short), network->num_vertices);

	int j = 0;
	for (int i = 0; i < network->num_vertices; i++) {
		if (network->adjacency[host][i] != 0) {
			list[j] = i;
			j++;
		}
	}

	for (int i = 0; i < j; i++) {
		for (int z = 0; z < network->num_vertices; z++) {
			if (network->adjacency[list[i]][z] == 1) {
				if (z == host) {
					1;
				} else {
					network->adjacency[host][z] = 1;
					network->adjacency[z][host] = 1;
					network->adjacency[list[i]][z] = 0;
					network->adjacency[z][list[i]] = 0;
					count_changes++;
				}
			}
		}
	}

	free(list);
	return count_changes;
}

// function that counts the number of connections for a specific host
int count_paths(net_p network, int select_host) {
	int count = 0;
	for (int i = 0; i < network->num_vertices; i++) {
		count += network->adjacency[select_host][i];
	}
	return count;
}

// Depth first search
void DFS(net_p network, int starting_node, int budget, int *visited) {
	int j;
	visited[starting_node] = 1;

	for (j = 0; j < network->num_vertices; j++) {
		if (visited[j] == 0 && network->adjacency[starting_node][j] == 1
				&& budget > 0) {
			budget = budget - access_cost;

			//check if node is attacked firewall or host
			if (!is_firewall(network, j)) {
				DFS(network, j, budget, visited);
			}

		}
	}
}

// Breadth first search
void BFS(net_p network, int starting_node, int budget, int *visited) {
	int *queue = (int *) calloc(sizeof(int), network->num_vertices);
	int front = 0;
	int rear = 0;
	visited[starting_node] = 1;
	queue[rear] = starting_node;
	rear++;

	while (rear != front) {
		int u = queue[front];
		front++;
		int i = 0;
		for (i = 0; i < network->num_vertices; i++) {
			if (visited[i] == 0 && network->adjacency[u][i] && budget > 0) {
				budget = budget - access_cost;

				//check if node is attacked firewall or host
				if (!is_firewall(network, i)) {
					queue[rear] = i;
					rear++;
				}

				visited[i] = 1;
			}
		}
	}
	free(queue);
}

// Copy a network from source to destination
void copy_network(net_p source, net_p destination) {
	*destination = *source;
}

// Counts the total number of resources occuring in a network.
int total_resource_count(net_p network) {
	int count = 0;

	for (int i = 0; i < network->num_vertices; i++) {
		count += network->nodes[i].resource.size();
	}
	return count;
}

// counts the number of paths, resources, hosts in a network
double *network_spatial_spread(net_p network,
		vector<vector<double> >& similarity, double *values) {
	//the number of paths
	int nr_paths = 0;
	for (int i = 0; i < network->num_vertices; i++) {
		for (int j = 0; j < network->num_vertices; j++) {
			values[0] += network->adjacency[i][j];
			nr_paths++;
		}
	}
	//values[0] = values[0] / 2;//since the network is undirected
	values[0] = values[0] / (network->num_vertices * network->num_vertices); //normalize

	//number of resources
	int nr = 0;
	for (int i = 0; i < network->num_vertices; i++) {
		nr = count_resources(network, i);
		values[1] += nr;
		if (nr > 1) {
			values[1] += resource_similarity_on_host(network, i, similarity);
		}
	}

	values[1] = values[1] / (network->num_vertices * max_resources_per_host);

	//number of hosts
	values[2] = network->num_vertices / max_network_size;
	return values;
}

// Calculate the resourcee similarity of resources occuring on a single host
double resource_similarity_on_host(net_p network, int select_host,
		vector<vector<double> >& similarity) {
	double result = 0;

	uint resources = network->nodes[select_host].resource.size();
	for (uint i = 0; i < resources - 1; i++) {
		for (uint j = i + 1; j < resources; j++) {
			result +=
					similarity[network->nodes[select_host].resource[i]][network->nodes[select_host].resource[j]];
		}
	}
	return result;
}

// Expands network with new hosts. Maybe stupid function name
void network_mangling(net_p network) {
	int size = (int) floor(network->num_vertices / 2.);

	while (size > 0) {
		size = size - add_host(network);
	}
}

// Displays resource similarity matrix
void display_resource_similarity(vector<vector<double> >& similarity,
		int size) {
	printf("Resource similarity is \n");
	for (int i = 0; i < size; i++) {
		for (int j = 0; j < size; j++) {
			printf("%lf ", similarity[i][j]);
		}
		printf("\n");
	}
}

// Displays the cost of successfully mounting every available exploit
void display_exploit_cost(int *cost, int size) {
	printf("Exploit cost is \n");
	for (int i = 0; i < size; i++) {
		printf("%d ", cost[i]);
	}
}

// Define the popularity of resources - the more popular resource, the more often it occurs in a network
void get_resource_popularity(uint *resource_popularity, int size) {
	int temp = 0;
	int flag = 0;
	int i = 0;

	for (i = 0; i < size; i++) {
		resource_popularity[i] = 0;
	}
	while (i < size) {
		temp = get_random_int(1, size);
		for (int j = 0; j < size; j++) {
			if (resource_popularity[j] == temp) {
				flag = 1;
			}
		}
		if (flag == 0) {
			resource_popularity[i] = temp;
			i++;
		}
		flag = 0;
	}
}


// returns 1 if firewall
// return 0 otherwise
int is_firewall(net_p network, int host) 
{
	return (network->nodes[host].firewall == true && network->nodes[host].exploited == false);
}


// mark firewall as exploited
void firewall_exploited(net_p network, int host) 
{
	network->nodes[host].exploited = true;
}


// display the network adjacency matrix
void display_network(net_p network, int log_to_file) {
	if (log_to_file == 0) {
		printf("Adjacency matrix\n");
		for (int i = 0; i < network->num_vertices; i++) {
			for (int j = 0; j < network->num_vertices; j++) {
				printf("%d ", network->adjacency[i][j]);
			}
			printf("\n");
		}
		printf("\n");
	} else {
		FILE *fout;
		if ((fout = fopen(network_file, "w+")) == NULL) {
			puts("Unable to open file for storing network\n");
			exit(0);
		}

		fprintf(fout, "Number of core vertices: %d\n", network->core_vertices);
		fprintf(fout, "Number of vertices: %d\n\n", network->num_vertices);

		fprintf(fout, "Adjacency matrix:\n");
		for (int i = 0; i < network->num_vertices; i++) {
			for (int j = 0; j < network->num_vertices; j++) {
				fprintf(fout, "%d ", network->adjacency[i][j]);
			}
			fprintf(fout, "\n");
		}
		fprintf(fout, "\n\n");

		for (int i = 0; i < network->num_vertices; i++) {
			fprintf(fout, "Host %d has resources ", i);
			for (int j = 0; j < network->max_resource_per_host; j++) {
				if (j != 0 && network->nodes[i].resource[j] != 0) {
					fprintf(fout, ", ");
				}
				if (network->nodes[i].resource[j] != 0) {
					fprintf(fout, "%d", network->nodes[i].resource[j]);
				}
			}
			fprintf(fout, "\n");
		}
		fprintf(fout, "\n");
		fclose(fout);
	}
}

// Display network with its properties. Does not have newer functionalities included
void network_stats(net_p network, vector<vector<double> >& similarity,
		int *exploit) {

	graphviz_network_stats(network, similarity, exploit, "gv_network.txt");

	FILE *fout;
	if ((fout = fopen(network_file, "w+")) == NULL) {
		puts("Unable to open file for storing network stats\n");
		exit(0);
	}

	fprintf(fout, "Number of core vertices: %d\n", network->core_vertices);
	fprintf(fout, "Number of vertices: %d\n\n", network->num_vertices);

	fprintf(fout, "Adjacency matrix:\n");
	for (int i = 0; i < network->num_vertices; i++) {
		for (int j = 0; j < network->num_vertices; j++) {
			fprintf(fout, "%d ", network->adjacency[i][j]);
		}
		fprintf(fout, "\n");
	}
	fprintf(fout, "\n\n");

	for (int i = 0; i < network->num_vertices; i++) {
		fprintf(fout, "Host %d has the following resources: ", i);
		for (uint j = 0; j < network->nodes[i].resource.size(); j++) {
			if (j != 0 && network->nodes[i].resource[j] != 0) {
				fprintf(fout, ", ");
			}
			if (network->nodes[i].resource[j] != 0) {
				fprintf(fout, "%d", network->nodes[i].resource[j]);
			}
		}
		fprintf(fout, "\n");
	}

	fprintf(fout, "\n");
	fprintf(fout, "Resource similarity is \n");
	for (int i = 0; i < (int) max_resources; i++) {
		for (int j = 0; j < (int) max_resources; j++) {
			fprintf(fout, "%lf ", similarity[i][j]);
		}
		fprintf(fout, "\n");
	}
	fprintf(fout, "\n");
	fprintf(fout, "Exploit cost is \n");
	for (int i = 0; i < (int) max_resources; i++) {
		fprintf(fout, "%d ", exploit[i]);
	}
	fclose(fout);
}

char * getNodeName(net_p network, int i) {
	if (network->nodes[i].real_node && !network->nodes[i].firewall) {
		return "node";
	}

	if (network->nodes[i].firewall) {
		return "firewall";
	}

	return "honeypot";

}

void graphviz_network_stats(net_p network, vector<vector<double> >& similarity,
		int *exploit, char filename[100]) {
	FILE *fout;
	if ((fout = fopen(filename, "w+")) == NULL) {
		puts("Unable to open file for storing graphviz network stats\n");
		exit(0);
	}

	fprintf(fout, "graph NETWORK {\n");

	//real node
	fprintf(fout, "/* Real nodes */\n");
	fprintf(fout, "node [shape = ellipse, style = filled, color = palegreen];\n");
	for (int i = 0; i < network->num_vertices; i++) {
		if (network->nodes[i].real_node && !network->nodes[i].firewall) {
			fprintf(fout, "%s_%d;\n", getNodeName(network, i), i);
		}
	}

	//firewall node
	fprintf(fout, "/* Firewall */\n");
	fprintf(fout, "node [shape = box, style = filled, color = lightgrey];\n");
	for (int i = 0; i < network->num_vertices; i++) {
		if (network->nodes[i].firewall) {
			fprintf(fout, "%s_%d;\n", getNodeName(network, i), i);
		}
	}

	//honeypot node
	fprintf(fout, "/* Honeypot */\n");
	fprintf(fout, "node [shape = box, style = \"rounded, filled\", color = skyblue];\n");
	for (int i = 0; i < network->num_vertices; i++) {
		if (!network->nodes[i].real_node) {
			fprintf(fout, "%s_%d;\n", getNodeName(network, i), i);
		}
	}

	for (int i = 0; i < network->num_vertices; i++) {
		for (int j = 0; j < network->num_vertices; j++) {
			if (i > j && network->adjacency[i][j] == 1) {

				if (network->nodes[i].exploited) {
					fprintf(fout, "%s_%d [style = \"dotted, filled\", color = grey38, fillcolor = lightcoral];\n", getNodeName(network, i), i);
				}

				if (network->nodes[j].exploited) {
					fprintf(fout, "%s_%d [style = \"dotted, filled\", color = grey38, fillcolor = lightcoral];\n", getNodeName(network, j), j);
				}


				//if honeypot
				if (!network->nodes[i].real_node || !network->nodes[j].real_node) {
					fprintf(fout, "edge[color = brown1]\n");
				} else {
					fprintf(fout, "edge[color = gray29]\n");
				}

				fprintf(fout, "%s_%d -- %s_%d;\n", getNodeName(network, i), i,
						getNodeName(network, j), j);
			}

		}
	}

	fprintf(fout, "}\n");
	fclose(fout);

}

// display resources for each host
void display_resources(net_p network) {
	for (int i = 0; i < network->num_vertices; i++) {
		for (uint j = 0; j < network->nodes[i].resource.size(); j++) {
			printf("%d ", network->nodes[i].resource[j]);
		}
		printf("\n");
	}
	printf("\n");
}
