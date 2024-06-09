//Zainub Siddiqui, CS333, Lab4
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <crypt.h>
#include <sys/time.h>

#include "thread_hash.h"

#ifndef FALSE
# define FALSE 0
#endif // FALSE
#ifndef TRUE
# define TRUE 1
#endif // TRUE

#define MAX_THREADS 24

//global variables
static char *input_file = NULL;
static char *output_file = NULL;
static char *dictionary_file = NULL;
static int num_threads = 1;
static int verbose = FALSE;
static int apply_nice = FALSE;
static int i_file_option = FALSE;
static int o_file_option = FALSE;
static int d_file_option = FALSE;

static char **hashed_passwords = NULL;
static char **dictionary_words = NULL;
static int num_hashed_passwords = 0;
static int num_dictionary_words = 0;
struct timeval start_time, end_time;
double thread_runtime = 0;
double total_runtime = 0;

// total alg counts
int total_DES_count = 0;
int total_NT_count = 0;
int total_MD5_count = 0;
int total_SHA256_count = 0;
int total_SHA512_count = 0;
int total_YESCRYPT_count = 0;
int total_GOST_YESCRYPT_count = 0;
int total_BCRYPT_count = 0;
int total_threads = 0;

//functions
void display_help(void);
void read_hashed_passwords(const char * filename);
void read_dictionary_words(const char * filename);
void *crack_passwords(void *tid);
double elapse_time(struct timeval *, struct timeval *);
int get_next_row(void);

/* structure to pass arguments to thread function
typedef struct {
    int thread_id;
} thread_arg_t; */

int get_next_row(void) {
	static int next_row = 0;
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	int cur_row = 0;

	pthread_mutex_lock(&lock);
	cur_row = next_row++;
	pthread_mutex_unlock(&lock);

	return cur_row;
}

double elapse_time(struct timeval *t0, struct timeval *t1)
{
    double et = (((double) (t1->tv_usec - t0->tv_usec))
            / MICROSECONDS_PER_SECOND)
        + ((double) (t1->tv_sec - t0->tv_sec));

    return et;
}

int main(int argc, char *argv[])
{
	int opt = -1;
	hash_algorithm_t algorithm = DES;
    //thread_arg_t *thread_args = NULL;
	pthread_t *threads = NULL;
	long tid = 0;
	FILE *outfile = NULL;

    (void)algorithm_string;
	(void)algorithm;

	// use getopt() to parse command line options
	while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
		switch(opt) {
			case 'i':
				i_file_option = TRUE;
                input_file = optarg;
                break;
			case 'o':
				o_file_option = TRUE;
				output_file = optarg;
				//overwrite file
				outfile = fopen(output_file, "w");
    			if (!outfile) 
				{
        			perror("Error opening output file");
				}
    			fclose(outfile);
				break;
			case 'd':
				d_file_option = TRUE;
				dictionary_file = optarg;
				break;
			case 't':
				num_threads = atoi(optarg);
				if (num_threads > MAX_THREADS)
					num_threads = MAX_THREADS;
				break;
			case 'v':
				verbose = TRUE;
				break;
			case 'h':
				display_help();
				exit(EXIT_SUCCESS);
				break;
			case 'n':
				apply_nice = TRUE;
				break;
			default:
	//			fprintf(stderr, "oopsie - unrecognized command line option \"%s\"\n", optarg);
				fprintf(stderr, "oopsie - unrecognized command line option \"%c\"\n", optopt);
				break;
		}
	}

	// check and apply nice 
	if (apply_nice)
		nice(NICE_VALUE);

	// verify for both -i and -d options
	if (!d_file_option)
	{
		fprintf(stderr, "must give name for dictionary input file with -d\n");
		exit(EXIT_FAILURE);
	}
	else if (!i_file_option && d_file_option)
	{
		fprintf(stderr, "must give name for hashed password input file with -i\n");
		exit(EXIT_FAILURE);
	}

	// read plain text and password file and store in arrays	
	read_hashed_passwords(input_file);
	read_dictionary_words(dictionary_file);

	if (verbose)
	{
		fprintf(stderr, "word count: %d\n", num_hashed_passwords);
		fprintf(stderr, "word count: %d\n", num_dictionary_words);
	}

	// time started for all threads
	gettimeofday(&start_time, NULL);

	threads = malloc(num_threads * sizeof(pthread_t));
    //thread_args = malloc(num_threads * sizeof(thread_arg_t));
	for (tid = 0; tid < num_threads; tid++) 
	{
        //thread_args[tid].thread_id = tid;
        pthread_create(&threads[tid], NULL, crack_passwords, (void *)tid);
	}
    for (tid = 0; tid < num_threads; tid++) 
	{
    	pthread_join(threads[tid], NULL);
    }

	free(threads);
//	free(thread_args);

	// time ended for all threads
	gettimeofday(&end_time, NULL);
    total_runtime = elapse_time(&start_time, &end_time);

	fprintf(stderr, "total:%4d %8.2lf sec              DES:%6d               NT:%6d              MD5:%6d           SHA256:%6d           SHA512:%6d         YESCRYPT:%6d    GOST_YESCRYPT:%6d           BCRYPT:%6d  total:%9d\n",
        total_threads, total_runtime, total_DES_count, total_NT_count, total_MD5_count, total_SHA256_count,
        total_SHA512_count, total_YESCRYPT_count, total_GOST_YESCRYPT_count, total_BCRYPT_count, num_hashed_passwords);

	// free hashed and dictionary words
	for (int i = 0; i < num_hashed_passwords; i++) {
   		free(hashed_passwords[i]);
	}
	free(hashed_passwords);

	for (int i = 0; i < num_dictionary_words; i++) {
    	free(dictionary_words[i]);
	}	
	free(dictionary_words);

	return EXIT_SUCCESS;
}

// read hashed password file and store in array
void read_hashed_passwords(const char * filename)
{
	char buffer[256];
	int index = 0;

	FILE *file = fopen(filename, "r");
	if (!file) {
        perror("Error opening hashed passwords file");
        return;
    }

    // Count the number of lines (hashed passwords)
    while (fgets(buffer, sizeof(buffer), file)) {
		++num_hashed_passwords;
	}

	// Allocate memory for hashed passwords
//	hashed_passwords = (char **)malloc(num_hashed_passwords * sizeof(char *));
	hashed_passwords = malloc(num_hashed_passwords * sizeof(char *));
	if (!hashed_passwords) {
		perror("Error allocating memory for hashed passwords");
		fclose(file);
		return;
	}

	rewind(file); // Go back to the start of the file
	
	// Read hashed passwords into the array
  	while (fgets(buffer, sizeof(buffer), file)) 
	{
		buffer[strlen(buffer) - 1] = '\0';
        hashed_passwords[index] = (char *)malloc((strlen(buffer) + 1) * sizeof(char));
        if (!hashed_passwords[index]) {
            perror("Error allocating memory for hashed password");
            fclose(file);
            return;
        }
        strcpy(hashed_passwords[index], buffer);
        index++;
    }	
	
    fclose(file);	
}

// read plain text file and store in array
void read_dictionary_words(const char * filename)
{
	char buffer[256];
	int index = 0;

	FILE *file = fopen(filename, "r");
	if (!file) {
        perror("Error opening hashed passwords file");
        return;
    }

    // Count the number of lines (dictionary words)
    while (fgets(buffer, sizeof(buffer), file)) {
		++num_dictionary_words;
	}

	// Allocate memory for hashed passwords
	//dictionary_words = (char **)malloc(num_dictionary_words * sizeof(char *));
	dictionary_words = malloc(num_dictionary_words * sizeof(char *));
	if (!dictionary_words) {
		perror("Error allocating memory for dictionary words");
		fclose(file);
		return;
	}

	rewind(file); // Go back to the start of the file
	
	// Read dictionary words into the array
  	while (fgets(buffer, sizeof(buffer), file)) 
	{
		buffer[strlen(buffer) - 1] = '\0';
        dictionary_words[index] = (char *)malloc((strlen(buffer) + 1) * sizeof(char));
        if (!dictionary_words[index]) {
            perror("Error allocating memory for dictionary word");
            fclose(file);
            return;
        }
        strcpy(dictionary_words[index], buffer);
        index++;
    }	
    fclose(file);	
}

// display help
void display_help(void) 
{
    fprintf(stderr, "help text\n");
    fprintf(stderr, "        ./thread_hash ...\n");
    fprintf(stderr, "        Options: i:o:d:hvt:n\n");
    fprintf(stderr, "                -i file         input file name (required)\n");
    fprintf(stderr, "                -o file         output file name (default stdout)\n");
    fprintf(stderr, "                -d file         dictionary file name (default stdout)\n");
    fprintf(stderr, "                -t #            number of threads to create (default 1)\n");
    fprintf(stderr, "                -v              enable verbose mode\n");
    fprintf(stderr, "                -h              helpful text\n");
}

// loop through words/passwords and crack
void *crack_passwords(void *tid)
{
    int DES_count = 0, NT_count = 0, MD5_count = 0, SHA256_count = 0, SHA512_count = 0, YESCRYPT_count = 0, GOST_YESCRYPT_count = 0, BCRYPT_count = 0;
//  thread_arg_t *args = (thread_arg_t *)arg;
//  int thread_id = args->thread_id;
    long thread_id = (long)tid;
    int total = 0;
    struct crypt_data data;
	int i = -1;
	int j = -1;
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    data.initialized = 0;

    gettimeofday(&start_time, NULL);

	for (i = get_next_row(); i < num_hashed_passwords; i = get_next_row()) {
        for (j = 0; j < num_dictionary_words; j++) {
				char *hashed = crypt_r(dictionary_words[j], hashed_passwords[i], &data);
				if (hashed && strcmp(hashed, hashed_passwords[i]) == 0) {
					if (hashed_passwords[i][0] != '$') {
						DES_count++;
					} else {
						switch (hashed_passwords[i][1]) {
							case '3': NT_count++; break;
							case '1': MD5_count++; break;
							case '5': SHA256_count++; break;
							case '6': SHA512_count++; break;
							case 'y': YESCRYPT_count++; break;
							case 'g': GOST_YESCRYPT_count++; break;
							default: if (hashed_passwords[i][2] == 'b') BCRYPT_count++; break;
						}
					}
					if (verbose) {
						fprintf(stderr, "thread%3ld: cracking %s\n", thread_id, hashed_passwords[i]);
					}
					if (o_file_option) {
						FILE *outfile = fopen(output_file, "a");
						if (outfile) {
							fprintf(outfile, "cracked  %s %s\n", dictionary_words[j], hashed_passwords[i]);
							fclose(outfile);
						} else {
							perror("Error opening output file");
						}
					} else {
						printf("cracked  %s %s\n", dictionary_words[j], hashed_passwords[i]);
					}
					total++;
            }
        }
    }

    gettimeofday(&end_time, NULL);
	thread_runtime = elapse_time(&start_time, &end_time);

    pthread_mutex_lock(&lock);
    total_DES_count += DES_count;
    total_NT_count += NT_count;
    total_MD5_count += MD5_count;
    total_SHA256_count += SHA256_count;
    total_SHA512_count += SHA512_count;
    total_YESCRYPT_count += YESCRYPT_count;
    total_GOST_YESCRYPT_count += GOST_YESCRYPT_count;
    total_BCRYPT_count += BCRYPT_count;
    total_threads++;
    pthread_mutex_unlock(&lock);

	fprintf(stderr, "thread:%3ld %8.2lf sec              DES:%6d               NT:%6d              MD5:%6d           SHA256:%6d           SHA512:%6d         YESCRYPT:%6d    GOST_YESCRYPT:%6d           BCRYPT:%6d  total:%9d\n",
            thread_id, thread_runtime, DES_count, NT_count, MD5_count, SHA256_count, SHA512_count, YESCRYPT_count, GOST_YESCRYPT_count, BCRYPT_count, total);

    pthread_exit(EXIT_SUCCESS);
}

