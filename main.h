#pragma once
#include <stdio.h>           
#include <stdlib.h>    
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

//#include "memory.h"
//#define malloc(X) my_malloc(X, __FILE__, __LINE__, __FUNCTION__)
//#define calloc(X, Y) my_calloc(X, Y, __FILE__, __LINE__, __FUNCTION__)
//#define free(X) my_free(X, __FILE__, __LINE__, __FUNCTION__)

typedef  unsigned int uint;

extern unsigned long long  seed;

extern uint scenario;
extern uint  runs;
extern uint pop_size_attack;
extern uint pop_size_defense;
extern uint genotype_size_attacker;
extern uint genotype_size_defender;

extern double ind_mut_prob_attack;
extern double ind_mut_prob_defense;

extern uint generations;
extern uint games;

extern uint max_honeypots;
extern uint defense_budget;
extern uint attack_budget;
extern uint max_resources;
extern uint max_resources_per_host;
extern uint num_ports;

extern uint min_value;
extern uint max_value;

extern uint network_size;
extern uint nr_real_nodes;
extern uint max_network_size;
extern uint type;

extern uint access_cost;
extern uint port_scan_cost;
extern uint diversify_resource;
extern uint wait_cost;
extern uint defense_cost;

extern double network_sparsity;

extern char name[100];
extern char parameters[100];
extern char pre_adj[100];
extern char pre_vul[100];

extern int *exploit_cost;

extern int attacker_objective;
extern int defender_objective;

extern uint log_level;

extern char final_output_file[100];
extern char network_file[100];

extern int preconfig;

extern double similarity_threshold;

extern int attacker_node;

extern uint *resource_popularity;

extern uint port_per_host;
extern double percentage_of_firewalls;