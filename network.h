#pragma once
#include "main.h"
#include<vector>
using namespace std;

typedef enum { UNDIRECTED = 0, DIRECTED = 1 } network_type;

// Network structure
typedef struct network_structure
{
	network_type type;        //Directed or undirected graph
	int num_vertices;         //Number of vertices
	int core_vertices;		//Number of the nodes that cannot change (real + honeypot)
	vector< vector<short> > adjacency;			// Adjacency matrix
	vector< vector<short> > last_adjacency;		// Previous adjacency matrix
	vector< vector<short> > resource;			// Resource list
	vector<short> real_nodes;		        //Nodes that cannot be changed and are not honeypots
	vector<short> detected_attacks;
	int num_detected;
	int max_resources;
	int max_resource_per_host;
	int max_network;
	double network_sparsity;
} net_t, *net_p;

net_p create_network(network_type type, int num_vertices, int max_network_size, double network_sparsity, int preconfig);
void display_network(net_p network, int log_to_file);
void delete_network(net_p network);
void create_resources(net_p network, int resources, int max_resources_per_host, int preconfig);
void display_resources(net_p network);
int add_host(net_p network);
int delete_host(net_p network);
int add_path(net_p network);
int delete_path(net_p network);
void change_path(net_p network);
int add_resource(net_p network, int select_host);
int delete_resource(net_p network, int select_host);
int count_resources(net_p network, int host);
int add_subnet(net_p network, int select_host);
int count_paths(net_p network, int select_host);
void DFS(net_p network, int starting_node, int budget, int *visited);
void BFS(net_p network, int starting_node, int budget, int *visited);
void copy_network(net_p source, net_p destination);
int total_resource_count(net_p network);
double *network_spatial_spread(net_p network, vector< vector<double> >& similarity, double *values);
double resource_similarity_on_host(net_p network, int select_host, vector< vector<double> >& similarity);
void network_mangling(net_p network);
void display_resource_similarity(vector< vector<double> >& similarity, int size);
void display_exploit_cost(int *cost, int size);
void network_stats(net_p network, vector< vector<double> >& similarity, int *exploit);
void get_resource_popularity(uint *resource_popularity, int size);

//double d1(net_p network);
//double similarity_sensitive_richness(net_p network, double **similarity);
//void change_host(net_p network);
//int count_subnets(net_p network, int select_host);
//int resource_richness(net_p network);
//void change_resource(net_p network);
