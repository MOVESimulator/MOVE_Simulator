#pragma once
//#include "main.h"
#include "network.h"
//#include "ga.h"
#include "helper.h"

double run_attack_move(net_p network, chromosome attackers[], int individual, vector< vector<double> >& similarity, int *exploit, int generation, int run, int current_game);
void find_neighborhood(net_p network, vector<int>& neighbors);
int create_attacker_node(net_p network);
