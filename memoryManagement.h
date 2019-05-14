//Jonathan Pham
//CS 4760 OS
//Memory Management
//Due: 05/08/19

#define STRUCT_SZ ((sizeof(rscArraySz)/sizeof(rscArraySz[0])) * 18)
#define SEM_SIZE sizeof(int)
#define QUE_SZ 18
#include <stdio.h>
#include <unistd.h>
#include <semaphore.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/msg.h>
#include <string.h>
#include <sys/wait.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <stdbool.h>
#ifndef FALSE
#define FALSE (0)
#endif
#ifndef TRUE
#define TRUE (!FALSE)
#endif

typedef struct memory_manager{
        pid_t pid;
        int resource_Marker;
        int tableSz[32];

} memory_manager;

struct memory_manager *rscArraySz[18];
struct memory_manager *(*rscArrayPointer)[] = &rscArraySz;

pid_t pid = 0;
extern int limit;
extern int percentage;

pid_t forkChild(char *sharedTimeMem, char *sharedSemMem, char*sharedPositionMem, char*rscShrdMem, char*sharedLimitMem, char*sharedPercentageMem){
        if((pid = fork()) == 0){
                execlp("./ass6", "./ass6", sharedTimeMem, sharedSemMem, sharedPositionMem, rscShrdMem, sharedLimitMem, sharedPercentageMem, NULL);
        }
        if(pid < 0){
                printf("Fork Error %s\n", strerror(errno));
        }
        return pid;
};

void makeShMem(int *timeid, int *semid, int*rscID, key_t timeKey, key_t semKey, key_t rscKey){
 
       *timeid = shmget(timeKey, (sizeof(unsigned int) * 2), 0666 | IPC_CREAT);
        *semid = shmget(semKey, (sizeof(unsigned int) * 2), 0666 | IPC_CREAT);
        *rscID = shmget(rscKey, (sizeof(memory_manager) *2),0666|IPC_CREAT);

        if(*timeid == -1){
                printf("Timed ID: %s\n", strerror(errno));
        }
        if(*semid == -1){
                printf("Semaphore ID: %s\n", strerror(errno));
        }
        if(*rscID == -1){
                printf("Resource ID:  %s\n", strerror(errno));
        }
};

void makeShMemKey(key_t *rscKey, key_t *semKey, key_t *timeKey) {
        *rscKey = ftok(".", 4328);
        *semKey = ftok(".", 8993);
        *timeKey = ftok(".", 2820);
};

void rsg_manage_args(char *sharedTimeMem, char *sharedSemMem, char*sharedPositionMem, char*rscShrdMem, char*sharedLimitMem, char*sharedPercentageMem, int timeid, int semid, int rscID, int placementMarker, int limit, int percentage){
        snprintf(sharedTimeMem, sizeof(sharedTimeMem)+25, "%d", timeid);
        snprintf(sharedSemMem, sizeof(sharedSemMem)+25, "%d", semid);
        snprintf(sharedPositionMem, sizeof(sharedPositionMem)+25, "%d", placementMarker);
        snprintf(rscShrdMem, sizeof(rscShrdMem)+25, "%d", rscID);
        snprintf(sharedLimitMem, sizeof(sharedLimitMem)+25, "%d", limit);
        snprintf(sharedPercentageMem, sizeof(sharedPercentageMem)+25, "%d", percentage);
};

void ShMemAttach(unsigned int **seconds, unsigned int **nanoseconds, sem_t **semaphore, memory_manager **rscPointer, int timeid, int semid, int rscID){
        *seconds = (unsigned int*)shmat(timeid, NULL, 0);
        if(**seconds == -1){
                printf("Seconds %s\n", strerror(errno));
        }
        *nanoseconds = *seconds + 1;
        if(**nanoseconds == -1){
                printf("Nanoseconds %s\n", strerror(errno));
        }
        *semaphore = (sem_t*)shmat(semid, NULL, 0);
        if(*semaphore == (void*)-1){
                printf("Semaphore %s\n", strerror(errno));
        }
        *rscPointer = (memory_manager*)shmat(rscID, NULL, 0);
        if(*rscPointer == (void*)-1){
                printf("Resource %s\n", strerror(errno));
        }
};
