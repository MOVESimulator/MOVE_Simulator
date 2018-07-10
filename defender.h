#pragma once
//#include "main.h"
#include "network.h"
#include "ga.h"

 double run_defense_move(net_p evolved_network, vector<int>& visited_nodes, chromosome defenders[], int individual, vector< vector<double> >& similarity);
 int find_attacker(net_p network, int* visited);