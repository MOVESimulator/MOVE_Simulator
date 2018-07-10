#include "main.h"
#include "helper.h"
#include"network.h"

//delete network
void delete_network(net_p network)
{
	free(network);
}

//create initial network with paths
net_p create_network(network_type type, int num_vertices, int max_network_size, double network_sparsity, int preconfig)
{
	net_p network = new net_t;
	network->type = type;
	network->core_vertices = num_vertices;
	network->num_vertices = num_vertices;
	network->max_network = max_network_size;
	network->network_sparsity = network_sparsity;

	network->adjacency.resize(network->max_network);
	for (int i = 0; i < network->max_network; i++) {
		network->adjacency[i].resize(network->max_network);
	}

	network->real_nodes.resize(network->core_vertices);
	network->detected_attacks.resize(network->max_network);

	if (preconfig == 1) {
		FILE *fout;
		int temp = 0;
		if ((fout = fopen(pre_adj, "r")) == NULL){
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
	}
	else {
		int node = 0;
		while (nr_real_nodes > 0) {
			node = get_random_int(0, network->core_vertices - 1);
			if (network->real_nodes[node] == 0) {
				network->real_nodes[node] = 1;
				nr_real_nodes--;
			}
		}
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
				if (network->real_nodes[i] == 1) {
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
			}
		}
		else { //for DIRECTED network
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
				if (network->real_nodes[i] == 1) {
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
	}

	network->last_adjacency = network->adjacency;

	return network;
}

//display the network adjacency matrix
void display_network(net_p network, int log_to_file)
{
	if (log_to_file == 0) {
		for (int i = 0; i < network->num_vertices; i++) {
			for (int j = 0; j < network->num_vertices; j++) {
				printf("%d ", network->adjacency[i][j]);
			}
			printf("\n");
		}
		printf("\n");
	}
	else {
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
				if (j != 0 && network->resource[i][j] != 0) {
					fprintf(fout, ", ");
				}
				if (network->resource[i][j] != 0) {
					fprintf(fout, "%d", network->resource[i][j]);
				}
			}
			fprintf(fout, "\n");
		}
		fprintf(fout, "\n");
		fclose(fout);
	}
}

void network_stats(net_p network, vector< vector<double> >& similarity, int *exploit)
{
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
		for (int j = 0; j < network->max_resource_per_host; j++) {
			if (j != 0 && network->resource[i][j] != 0) {
				fprintf(fout, ", ");
			}
			if (network->resource[i][j] != 0) {
				fprintf(fout, "%d", network->resource[i][j]);
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

//display resources for each host
void display_resources(net_p network)
{
	for (int i = 0; i < network->num_vertices; i++) {
		for (int j = 0; j < network->max_resource_per_host; j++) {
			if (network->resource[i][j] != 0) {
			printf("%d ", network->resource[i][j]);
			}
		}
		printf("\n");
	}
	printf("\n");
}


//create initial resources, 1 per host
void create_resources(net_p network, int resources, int max_resources_per_host, int preconfig)
{
	network->max_resources = resources;
	network->max_resource_per_host = max_resources_per_host;

	network->resource.resize(network->max_network);
	for (int i = 0; i < network->max_network; i++) {
		network->resource[i].resize(max_resources_per_host);
	}

	for (int i = 0; i < network->max_network; i++) {
		for (int j = 0; j < network->max_resource_per_host; j++) {
			network->resource[i][j] = 0;
		}
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
				network->resource[i][j] = temp;
			}
		}
		fclose(fout);
	}
	else {
		for (int i = 0; i < network->num_vertices; i++) {
			network->resource[i][0] = get_random_int(1, network->max_resources);
		}
	}	
}

//add a resource, if success return 1, else 0
int add_resource(net_p network, int select_host)
{
	int flag1 = 1;
	int flag2 = 1;
	int count = 0;
	int resource;
	int count2 = 0;
	int host;

	if (select_host == -1) {
		while (flag2) {
			// first affect on detected, then random
			host = get_random_int(0, network->num_vertices - 1);
			if(network->num_detected > 0) {
				while(network->detected_attacks[host] != 1)
					host = (host + 1) % network->num_vertices;
				// reset selected
				network->detected_attacks[host] = 0;
				network->num_detected--;
			}

			if (count_resources(network, host) < network->max_resource_per_host) {
				flag2 = 0;
			}
			else {
				count++;
			}
			if (count == (network->num_vertices*network->max_resource_per_host)) {
				return 0;
			}
		}
	}
	else {
		host = select_host;
	}

	count = 0;
	while (flag1) {
		resource = get_random_int(1, network->max_resources);
		for (int i = 0; i < network->max_resource_per_host; i++) {
			if (resource == network->resource[host][i]) {
				count++;
				count2++;
			}
		}
		if (count == 0) {
			network->resource[host][count_resources(network, host)] = resource;
			flag1 = 0;
		}
		count = 0;
		if (count2 > network->max_resource_per_host*network->max_resources / 2) {
			return 0;
		}
	}
	return 1;
}

//add a host, if success return 1, else 0. If the network equals full size, then first delete a node and then create a node
int add_host(net_p network)
{
	if (network->num_vertices == network->max_network) {
		delete_host(network);
	}

	if (network->num_vertices == network->max_network) {
		return 0;
	}
	else {
		network->num_vertices++;
		if (type == UNDIRECTED) {
			for (int i = 0; i < network->num_vertices; i++) {
				if (get_random_double() >= network->network_sparsity || 
					(network->detected_attacks.size() == network->num_vertices && network->detected_attacks[i] == 1)) {
					network->adjacency[network->num_vertices-1][i] = 1;
					network->adjacency[i][network->num_vertices-1] = 1;
				}
				else {
					network->adjacency[network->num_vertices-1][i] = 0;
					network->adjacency[i][network->num_vertices-1] = 0;
				}
			}
		}
		else {
			for (int i = 0; i < network->num_vertices; i++) {
				if (get_random_double() >= network->network_sparsity) {
					network->adjacency[network->num_vertices-1][i] = 1;
				}
				else {
					network->adjacency[network->num_vertices-1][i] = 0;
				}
			}
		}
		add_resource(network, network->num_vertices - 1);

		return 1;
	}
}

//delete a host, return 1 if success, 0 otherwise. Core nodes cannot be deleted
int delete_host(net_p network)
{
	if (network->core_vertices < network->num_vertices) {
		// TODO: first choose detected, then random
		if(network->num_detected > 0) {

		}

		int del = get_random_int(network->core_vertices, network->num_vertices - 1);

		// reset del-th element in data structures
		network->adjacency[del].assign(network->max_network, 0);
		network->last_adjacency[del].assign(network->max_network, 0);
		for (int i = 0; i < network->num_vertices - 1; i++) {
			network->adjacency[i][del] = 0;
			network->last_adjacency[i][del] = 0;
		}

		network->resource[del].assign(network->max_resource_per_host, 0);

		network->num_vertices--;
		return 1;
	}
	else {
		return 0;
	}
}

//function that adds a path, if success return 0, otherwise 1
int add_path(net_p network)
{
	int flag = 1;
	int count = 0;
	while (flag){
		// first choose detected, then random
		int source = get_random_int(0, network->num_vertices - 1);
		if(network->num_detected > 0) {
			while(network->detected_attacks[source] != 1)
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
			}
			else {
				network->adjacency[source][destination] = 1;
				flag = 0;
			}
		}
		else {
			count++;
		}
		if (count == (network->num_vertices*network->num_vertices) && flag == 1) {
			return 0;
		}
	}
	return 1;
}

//function to delete a path, on success return 1, else 0
int delete_path(net_p network)
{
	int flag = 1;
	int count = 0;
	while (flag) {
		if (count == (network->num_vertices*network->num_vertices) && flag == 1) {
			return 0;
		}

		// first choose detected, then random
		int source = get_random_int(0, network->num_vertices - 1);
		if(network->num_detected > 0) {
			while(network->detected_attacks[source] != 1)
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
		if(source < network->core_vertices && network->real_nodes[source] == 1) {
			int connections = 0;
			for(int i = 0; i < network->num_vertices && connections < 2; i++)
				connections += network->adjacency[source][i];
			if(connections < 2) {
				count++;
				continue;
			}
		}

		if(destination < network->core_vertices && network->real_nodes[destination] == 1) {
			int connections = 0;
			for(int i = 0; i < network->num_vertices && connections < 2; i++)
				connections += network->adjacency[source][i];
			if(connections < 2) {
				count++;
				continue;
			}
		}

		if (network->adjacency[source][destination] == 1) {
			if (type == UNDIRECTED) {
				network->adjacency[source][destination] = 0;
				network->adjacency[destination][source] = 0;
				flag = 0;
			}
			else {
				network->adjacency[source][destination] = 0;
				flag = 0;
			}
		}
		else {
			count++;
		}

	}
	return 1;
}

//function that combines delete_path and add_path functionalities. Currently not used
void change_path(net_p network)
{
	delete_path(network);
	add_path(network);
}

//count the number of resources for a specific host
int count_resources(net_p network, int host)
{
	int count = 0;
	for (int i = 0; i < network->max_resource_per_host; i++) {
		if (network->resource[host][i] != 0) {
			count++;
		}
	}
	return count;
}

//function that deletes a resource. If success return 1, else 0
int delete_resource(net_p network, int select_host)
{
	int flag = 1;
	int temp = 0;
	int host;
	if (select_host == -1) {
		while (flag && temp < (network->num_vertices * network->num_vertices)) {
			host = get_random_int(0, network->num_vertices - 1);
			if(network->num_detected > 0) {
				while(network->detected_attacks[host] != 1)
					host = (host + 1) % network->num_vertices;
			}
			if (count_resources(network, host) > 1) {
				// reset if selected
				network->detected_attacks[host] = 0;
				network->num_detected--;
				flag = 0;
			}
			temp++;
		}
	}
	else {
		for (int i = 0; i < network->max_resource_per_host; i++) {
			network->resource[select_host][i] = 0;
			return 0; //return 0 since host is also deleted
		}
	}

	if (flag == 1 && select_host == -1) {
		return 0; //could not find resource to delete
	}
	
	if (select_host == -1) {
		int count = count_resources(network, host);

		// if there is a single resource on the selected real_nodes host
		if(host < network->core_vertices && network->real_nodes[host] == 1 && count == 1)
			return 0;

		// remove resource that is not the first resource on a real_node
		int resource_position;
		do {
			resource_position = get_random_int(0, count - 1);
		} while(host < network->core_vertices && network->real_nodes[host] == 1 && resource_position == 0);

		for (int i = resource_position; i < network->max_resource_per_host - 1; i++) {
			network->resource[host][i] = network->resource[host][i + 1];
		}
		network->resource[host][count - 1] = 0;
		return 1;
	}
}

//currently works only for undirected networks. Not working at all??
int add_subnet(net_p network, int select_host) 
{
	int host;
	int flag = 1;
	int count_changes = 0;

	if (select_host == -1) {
		while (flag) {
			host = get_random_int(0, network->num_vertices - 1);
			if (count_paths(network, host) >= 2 && count_paths(network, host) < network->num_vertices - 1) {
				flag = 0;
			}
		}
	}
	else {
		host = select_host;
	}

	short *list = (short *)calloc(sizeof(short), network->num_vertices);

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
				}
				else {
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

//function that counts the number of connections for a specific host
int count_paths(net_p network, int select_host)
{
	int count = 0;
	for (int i = 0; i < network->num_vertices; i++) {
		count += network->adjacency[select_host][i];
	}
	return count;
}

void DFS(net_p network, int starting_node, int budget, int *visited)
{
	int j;
	visited[starting_node] = 1;

	for (j = 0; j < network->num_vertices; j++) {
		if (visited[j] == 0 && network->adjacency[starting_node][j] == 1 && budget > 0) {
			budget = budget - scan_cost;
			DFS(network, j, budget, visited);
		}
	}
}

void BFS(net_p network, int starting_node, int budget, int *visited)
{
	int *queue = (int *)calloc(sizeof(int), network->num_vertices);
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
				budget = budget - scan_cost;
				queue[rear] = i;
				rear++;
				visited[i] = 1;
			}
		}
	}
	free(queue);
}

//Copy a network from source to destination
void copy_network(net_p source, net_p destination)
{	
	destination->type = source->type;
	destination->core_vertices = source->core_vertices;
	destination->network_sparsity = source->network_sparsity;
	destination->num_vertices = source->num_vertices;
	destination->max_resources = source->max_resources;
	destination->max_network = source->max_network;
	destination->max_resource_per_host = source->max_resource_per_host;

	// copy vectors and matrices
	destination->adjacency = source->adjacency;
	destination->resource = source->resource;
	destination->real_nodes = source->real_nodes;
	destination->last_adjacency = source->last_adjacency;
}

int total_resource_count(net_p network)
{
	int count = 0;

	for (int i = 0; i < network->num_vertices; i++) {
		for (int j = 0; j < network->max_resource_per_host; j++) {
			if (network->resource[i][j] != 0) {
				count++;
			}
		}
	}
	return count;
}

double *network_spatial_spread(net_p network, vector< vector<double> >& similarity, double *values)
{
	//the number of paths
	int nr_paths = 0;
	for (int i = 0; i < network->num_vertices; i++) {
		for (int j = 0; j < network->num_vertices; j++) {
			values[0] += network->adjacency[i][j];
			nr_paths++;
		}
	}
	//values[0] = values[0] / 2;//since the network is undirected
	values[0] = values[0] / (network->num_vertices*network->num_vertices); //normalize


	//number of resources
	int nr= 0;
	for (int i = 0; i < network->num_vertices; i++) {
		nr = count_resources(network, i);
		values[1] += nr;
		if (nr > 1) {
			values[1] += resource_similarity_on_host(network, i, similarity);
		}
	}

	values[1] = values[1] / (network->num_vertices*max_resources_per_host);
	
	//number of nodes
	values[2] = network->num_vertices/ max_network_size;
	return values;
}

double resource_similarity_on_host(net_p network, int select_host, vector< vector<double> >& similarity)
{
	double result = 0;

	for (int i = 0; i < network->max_resource_per_host-1; i++) {
		for (int j = i + 1; j < network->max_resource_per_host; j++) {
			if (network->resource[select_host][j] != 0) {
				if (network->resource[select_host][i] == 0) {
					printf("Problem for %d %d\n", select_host, i);
				}
				result += similarity[network->resource[select_host][i]-1][network->resource[select_host][j]-1];
			}
		}
	}
	return result;
}

void network_mangling(net_p network)
{
	int size = (int) floor(network->num_vertices/2.);
	
	while (size > 0) {
		size = size - add_host(network);
	}
}

void display_resource_similarity(vector< vector<double> >& similarity, int size)
{
	printf("Resource similarity is \n");
	for (int i = 0; i < size; i++) {
		for (int j = 0; j < size; j++) {
			printf("%lf ", similarity[i][j]);
		}
		printf("\n");
	}
}

void display_exploit_cost(int *cost, int size)
{
	printf("Exploit cost is \n");
	for (int i = 0; i < size; i++) {
		printf("%d ", cost[i]);
	}
}

void get_resource_popularity(uint *resource_popularity, int size)
{
	int temp = 0;
	int flag = 0;
	int i = 0;
	
	for (i = 0; i < size; i++) {
		resource_popularity[i] = 0;
	}
	while(i < size){
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







//double d1(net_p network)
//{
//	double result = 1.0;
//
//	double *p = (double *)calloc(sizeof(double), network->vulnerability);
//	double total = (double)total_resource_count(network);
//
//	for (int j = 0; j < network->vulnerability; j++) {
//		for (int i = 0; i < network->num_vertices; i++) {
//			for (int z = 0; z < network->vulnerability; z++) {
//				if (network->vul[i][z] == (j + 1)) {
//					p[j] += 1;
//				}
//			}
//		}
//	}
//
//	for (int i = 0; i < network->vulnerability; i++) {
//		p[i] = (double)p[i] / (double)total;
//	}
//
//	for (int i = 0; i < network->num_vertices; i++) {
//		result = result * pow(p[i], p[i]);
//	}
//	free(p);
//
//	result =  1. / result;
//
//	return result;// / total;
//}


//larger value means lower similarity
//double similarity_sensitive_richness(net_p network, double **similarity)
//{
//	double result = 1.0;
//	double *p = (double *)calloc(sizeof(double), (network->max_resources + 1));
//	double *zp = (double *)calloc(sizeof(double), (network->max_resources + 1));
//
//	double total = (double)total_resource_count(network);
//
//	for (int j = 1; j <= network->max_resources; j++) {
//		for (int i = 0; i < network->num_vertices; i++) {
//			for (int z = 0; z <= network->max_resource_per_host; z++) {
//				if (network->resource[i][z] == j) {
//					p[j] += 1;
//				}
//			}
//		}
//	}
//
//	for (int i = 1; i <= network->max_resources; i++) {
//		p[i] = (double)p[i] / (double)total;
//	}
//
//
//	for (int i = 1; i <= network->max_resources; i++) {
//		for (int j = 1; j <= network->max_resources; j++) {
//			zp[i] += similarity[i][j] * p[j];
//		}
//	}
//
//	for (int i = 1; i <= network->max_resources; i++) {
//		result = result * pow(zp[i], p[i]);
//	}
//	free(p);
//	free(zp);
//
//	return 1. / result;;// / total;
//}

//function that combines delete and add host, currently not used
//void change_host(net_p network)
//{
//	delete_host(network);
//	add_host(network);
//}

//int count_subnets(net_p network, int select_host)
//{
//	int count = 0;
//	int temp = 0;
//	for (int i = 0; i < network->num_vertices; i++) {
//		if (network->adj[select_host][i] == 1) {
//			for (int j = 0; j < network->num_vertices; j++) {
//				temp += network->adj[i][j];
//			}
//			if (temp == 1) {
//				count++;
//			}
//			temp = 0;
//		}
//	}
//	return count;
//}

//int resource_richness(net_p network)
//{
//	int count = 0;
//	int *list = (int *)calloc(sizeof(int), network->max_resources);
//
//	for (int i = 0; i < network->num_vertices; i++) {
//		for (int j = 0; j < network->max_resource_per_host; j++) {
//			list[network->resource[i][j]] = 1;
//		}
//	}
//
//	for (int i = 0; i < network->max_resources; i++) {
//		count += list[i];
//	}
//	free(list);
//	return count;
//}

//function that combines the deletion and adding of resource. Currently not used
//void change_resource(net_p network)
//{
//	delete_resource(network, -1);
//	add_resource(network, -1);
//}
