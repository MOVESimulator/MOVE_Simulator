#pragma once
//#include "main.h"
#include "ga.h"
#include<vector>
using namespace std;

int get_random_int(int min, int max);
double get_random_double();
int HW(int n);

void validate_command_line(int argc, char* argv[], char parameters[]);
void get_parameters(char parfile[]);
void get_resource_similarity(vector< vector<double> >& res_similarity, int size);
void get_vulnerability_cost(int *exploit_cost, int size, int budget);
void logging(char *name, int log_level, int generation, chromosome population[], int pop_size, char *pop);
void final_stats(char *name,  int run, chromosome defenders[], int pop_size_defense, chromosome attackers[], int pop_size_attack, int generations);