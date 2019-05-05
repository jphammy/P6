//Jonathan Pham
//CS 4760 OS
//Memory Management
//Due: 05/08/19

#include "memoryManagement.h"
#define SECOND_TIMER 100

int alrm, processCount, frameTablePos = 0;
int setArr[18] = {0};

struct memory_resource {
    long msgString;
    char msgChar[100];
} message;

void timerKiller(int sign_no){
        alrm = 1;
}

int arrayChecker(int *placementMarker){
        int inc = 0;
        for(inc = 0; inc < processCount; inc++){
                if(setArr[inc] == 0){
                        setArr[inc] = 1;
                        *placementMarker = inc;
                        return 1;
                }
        }
        return 0;
}

void segFaultCatcher(int signal, siginfo_t *si, void *arg){
        fprintf(stderr, "Caught segfault at address %p\n", si->si_addr);
        kill(0, SIGTERM);
}

void timeToFork(unsigned int *seconds, unsigned int *nanoseconds, unsigned int *forkTimeSeconds, unsigned int *forkTimeNanoseconds){
        unsigned int random = rand()%500000000;//1000000000;
        *forkTimeNanoseconds = 0;
        *forkTimeSeconds = 0;
        if((random + nanoseconds[0]) >=1000000000){
                *forkTimeSeconds += 1;
                *forkTimeNanoseconds = (random + *nanoseconds) - 1000000000;
        } else {
                *forkTimeNanoseconds = random + *nanoseconds;
        }
        *forkTimeSeconds = *seconds;// + rand()%2;
}

int main(int argc, char *argv[]){
        struct sigaction sa;
        memset(&sa, 0, sizeof(struct sigaction));
        sigemptyset(&sa.sa_mask);
        sa.sa_sigaction = segFaultCatcher;
        sa.sa_flags = SA_SIGINFO;
        sigaction(SIGSEGV, &sa, NULL);


        char childMsg[20], ch;
        char requestType[20];
	char sharedPositionMem[10]; 	
	char sharedPercentageMem[10]; 
        char sharedTimeMem[10]; 
	char rscShrdMem[10]; 
	char sharedSemMem[10]; 
	char sharedLimitMem[10];

        int address;
        int forked = 0;
	int lines = 0; 
	int frameLoop = 0; 
	int pagefault = 0; 
	int requests = 0;
	int initialFork = 0;
	int j = 0, i = 0;
	int tempPid = 0; 
	int status; 

        unsigned int *seconds = 0; 
	unsigned int *nanoseconds = 0; 
	unsigned int forkTimeSeconds = 0; 
	unsigned int forkTimeNanoseconds = 0; 
	unsigned int accessSpeed = 0;

        srand(time(NULL));
        char* filename = malloc(sizeof(char));
        filename = "log.txt";
        FILE *infile = fopen(filename, "w");
        freopen("log.txt","a",infile);
        char opt;
        processCount = 18;
        int percentage = 50, maxProcL = 900;
        int frameTable[256][3] = {{0}};
        while((opt = getopt(argc, argv, "hp:x:l:")) != -1){
                switch(opt){
                        case'h':
                                printf("Number of processes spawned [default 18]\n-x: Percent of read reqest [default 50]. Write requests take up the remaining percentage. Accepts 0-99.\n-l: Changes the limit of requests made before a process checks for a 75 percent chance of termination (default 900). Accepts 1-2000.\n");
                                exit(0);
                        case'p':
                                processCount = atoi(optarg);
                                if (processCount > 18){
                                        processCount = 18;
                                }
                        case'x':
                                percentage = atoi(optarg);
                                if(percentage > 99 || percentage < 0){
                                        percentage = 50;
                                }
                        case'l':
                                maxProcL = atoi(optarg);
                                if(maxProcL > 2000 || maxProcL < 0){
                                        maxProcL = 900;
                                }
                }
        }

        key_t msgKey = ftok(".", 432820), timeKey = 0, rscKey = 0, semKey = 0;
        int msgid = msgget(msgKey, 0666 | IPC_CREAT), timeid = 0, rscID = 0, semid = 0, placementMarker = 0;

        memory_manager *rscPointer = NULL;
        sem_t *semPtr = NULL;
        makeShMemKey(&timeKey, &semKey, &rscKey);
        makeShMem(&timeid, &semid, &rscID, timeKey, semKey, rscKey);
        ShMemAttach(&seconds, &nanoseconds, &semPtr, &rscPointer, timeid, semid, rscID);
        double pageFaults = 0, memoryAccesses = 0, memoryAccessesPerSecond = 0;
        float childRequestAddress = 0;
        signal(SIGALRM, timerKiller);
        alarm(2);
        do {
                if(initialFork == 0){
                        timeToFork(seconds, nanoseconds, &forkTimeSeconds, &forkTimeNanoseconds);
                        initialFork = 1;
                        fprintf(infile, "Master: Fork Time starts at %d : %d\n", forkTimeSeconds, forkTimeNanoseconds);
                }
                *nanoseconds += 50000;
                if(*nanoseconds >= 1000000000){
                        *seconds += 1;
                        *nanoseconds = 0;
                        memoryAccessesPerSecond = (memoryAccesses/ *seconds);
                }
                if(((*seconds == forkTimeSeconds) && (*nanoseconds >= forkTimeNanoseconds)) || (*seconds > forkTimeSeconds)){
                        if(arrayChecker(&placementMarker) == 1){
                                forked++;
                                initialFork = 0;
                                fprintf(infile,"Master: Forking at %d : %d \n", *seconds, *nanoseconds);
                                rsg_manage_args(sharedTimeMem, sharedSemMem, sharedPositionMem, rscShrdMem, sharedLimitMem, sharedPercentageMem, timeid, semid, rscID, placementMarker, maxProcL, percentage);
                                pid_t childPid = forkChild(sharedTimeMem, sharedSemMem, sharedPositionMem, rscShrdMem, sharedLimitMem, sharedPercentageMem);
                                rscArraySz[placementMarker] = malloc(sizeof(struct memory_manager));
                                (*rscArrayPointer)[placementMarker]->pid = childPid;

                                fprintf(infile,"Master: Child %d spawned with corresponding PID %d\n", placementMarker, childPid);
                                for(i = 0 ; i < 32; i++){
                                        (*rscArrayPointer)[placementMarker]->tableSz[i] = -1;
                                }
                                (*rscArrayPointer)[placementMarker]->resource_Marker = 1; // pointer to an array os pointers to structsd

                        }
                }
                for(i = 0; i < processCount; i++){

                        if(setArr[i] == 1){

                                tempPid =  (*rscArrayPointer)[i]->pid;

                                if((msgrcv(msgid, &message, sizeof(message)-sizeof(long), tempPid, IPC_NOWAIT|MSG_NOERROR)) > 0){
                                        if(atoi(message.msgChar) != 99999){ //it received  aread or write
                                                fprintf(infile, "Master: P%d requesting address %d to ",i ,atoi(message.msgChar));
                                                strcpy(childMsg, strtok(message.msgChar, " "));
                                                address = atoi(childMsg);
                                                strcpy(requestType, strtok(NULL, " "));
                                                if(atoi(requestType) == 0){
                                                        fprintf(infile, "be read at time %d : %d\n", *seconds, *nanoseconds);
                                                }else{
                                                        fprintf(infile, "be written at time %d : %d\n", *seconds, *nanoseconds);
                                                }
                                                childRequestAddress = (atoi(childMsg))/1000;
                                                childRequestAddress = (int)(floor(childRequestAddress));
                                                if((*rscArrayPointer)[i]->tableSz[(int)childRequestAddress] == -1 || frameTable[(*rscArrayPointer)[i]->tableSz[(int)childRequestAddress]][0] != (*rscArrayPointer)[i]->pid){//if the page table position is empty or the pagetable frame position no longer is associated with the child request address
                                                        //assign to Frame Table
                                                        //need to check if pagetable[childrequestaddress] isnt -1;
                                                        //if frame table at frameTable[childRequestAddress][0]
                                                        frameLoop = 0;
                                                        while(frameTable[frameTablePos][0] != 0 && frameLoop < 255){ // Check for first empty frame
                                                                frameTablePos++;
                                                                frameLoop++;
                                                                if(frameTablePos == 256){
                                                                        frameTablePos = 0;
                                                                }
                                                                if(frameLoop == 255){
                                                                        pagefault = 1;
                                                                }
                                                        }
                                                        if(pagefault == 1){ 
                                                                pageFaults++;
                                                                fprintf(infile, "Master: Address %d is not in a frame, pagefault\n", address);
                                                                while(frameTable[frameTablePos][1] != 0){ //Check for second frame if it exists
                                                                        frameTable[frameTablePos][1] = 0; //Set to 0 if it was 1
                                                                        frameTablePos++; //then move position
                                                                        if(frameTablePos == 256){
                                                                                frameTablePos = 0;
                                                                        }
                                                                } 
                                                                if(frameTable[frameTablePos][1] == 0){
                                                                        memoryAccesses++;
                                                                        fprintf(infile, "Master: Clearing frame %d and swapping in P%d page %d\n", frameTablePos, i, (int)childRequestAddress);
                                                                        //new page goes here
                                                                        (*rscArrayPointer)[i]->tableSz[(int)childRequestAddress] = frameTablePos;
                                                                        frameTable[frameTablePos][0] = (*rscArrayPointer)[i]->pid;//(int)childRequestAddress;
                                                                        frameTable[frameTablePos][2] = atoi(requestType);
                                                                        fprintf(infile, "Master: Address %d in frame %d giving data to P%d at time %d : %d\n", address, frameTablePos, i, *seconds, *nanoseconds);
                                                                        frameTablePos++; //clock advances
                                                                        if(frameTablePos == 256){
                                                                                frameTablePos = 0;
                                                                        }
                                                                        requests++;
                                                                }
                                                                accessSpeed +=  15000000;
                                                                *nanoseconds += 15000000;
                                                                fprintf(infile, "Master: Dirty bit is set to %d and clock is incremented 15ms\n", atoi(requestType));
                                                        } else { //if it finds a place with an empty frame
                                                                memoryAccesses++;
                                                                (*rscArrayPointer)[i]->tableSz[(int)childRequestAddress] = frameTablePos; 
                                                                frameTable[frameTablePos][0] = (*rscArrayPointer)[i]->pid;//(int)childRequestAddress;
                                                                frameTable[frameTablePos][1] = 0;//R is cleared
                                                                frameTable[frameTablePos][2] = atoi(requestType);
                                                                fprintf(infile, "Master: Address %d in frame %d giving data to P%d at time %d : %d\n", address, frameTablePos, i, *seconds, *nanoseconds);
                                                                frameTablePos++; //clock advances.
                                                                if(frameTablePos == 256){
                                                                        frameTablePos = 0;
                                                                }
                                                                accessSpeed  += 10000000;
                                                                *nanoseconds += 10000000;
                                                                requests++;
                                                                fprintf(infile, "Master: Dirty bit is set to %d and and is incremented an addtional 10ms to the clock\n", atoi(requestType));
                                                        }

                                                } else {
                                                        memoryAccesses++;
                                                        frameTable[(*rscArrayPointer)[i]->tableSz[(int)childRequestAddress]][1] = 1; //reference bit set
                                                        frameTable[(*rscArrayPointer)[i]->tableSz[(int)childRequestAddress]][2] = atoi(requestType); //Dirty Bit is set MAYBE CHANGE THIS TO PROCESS NUMBER
                                                        *nanoseconds += 10000000;
                                                        accessSpeed +=  10000000;
                                                        requests++; 
                                                        fprintf(infile, "Master: Dirty bit is set to %d and is incremented an addtional 10ms to the clock\n", atoi(requestType));
                                                }

                                                message.msgString = ((*rscArrayPointer)[i]->pid+118);
                                                sprintf(message.msgChar,"wakey");
                                                msgsnd(msgid, &message, sizeof(message)-sizeof(long), 0);

                                        } else if(atoi(message.msgChar) == 99999){ 
                                                setArr[i] = 0; //basically if it received a message then it wants to die
                                                message.msgString = ((*rscArrayPointer)[i]->pid+118);
                                                fprintf(infile, "Master: P%d is complete! Clearing frames: ", i);
                                                for(j = 0; j < 32; j++){

                                                        if((*rscArrayPointer)[i]->tableSz[j] != -1 && frameTable[(*rscArrayPointer)[i]->tableSz[j]] == (*rscArrayPointer)[i]->tableSz[j]){
                                                                fprintf(infile, "%d, ", j);
                                                                frameTable[(*rscArrayPointer)[i]->tableSz[j]][0] = 0;
                                                                frameTable[(*rscArrayPointer)[i]->tableSz[j]][1] = 0;
                                                                frameTable[(*rscArrayPointer)[i]->tableSz[j]][2] = 0;
                                                                (*rscArrayPointer)[i]->tableSz[j] = -1;
                                                        }
                                                }
                                                fprintf(infile,"\n");
                                                sprintf(message.msgChar,"wakey");
                                                msgsnd(msgid, &message, sizeof(message)-sizeof(long), 0);
                                                waitpid(((*rscArrayPointer)[i]->pid), &status, 0);
                                                free(rscArraySz[i]);
                                        }

                                } else {
                                }
                        }
                }
                while((ch = fgetc(infile)) != EOF){
                        if(ch == '\n'){
                                lines++;
                        }
                }
                if(lines >= 100000){
                        fclose(infile);
                }

        }while((*seconds < SECOND_TIMER+10000) && alrm == 0 && forked < 100);
        fprintf(infile, "\nMaster: \n\tProgram is complete!!! Statistics are as follows:\n\t%f memory accesses per second.\n\t%f pagefaults per memory access.\n\t%f average access speed in nanoseconds.\n\t%d forks.\n\n", memoryAccessesPerSecond, pageFaults/memoryAccesses, accessSpeed/memoryAccesses, forked);

        fclose(infile);
        shmdt(seconds);
        shmdt(semPtr);
        shmdt(rscPointer);
        msgctl(msgid, IPC_RMID, NULL);
        shmctl(msgid, IPC_RMID, NULL);
        shmctl(rscID, IPC_RMID, NULL);
        shmctl(timeid, IPC_RMID, NULL);
        shmctl(semid, IPC_RMID, NULL);
        kill(0, SIGTERM);
        return ( 0 );
}
