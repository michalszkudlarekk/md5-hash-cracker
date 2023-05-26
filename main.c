#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <openssl/evp.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>

#define DICT_SIZE 1000
#define BUF_SIZE 128
#define DICT_FILE "test-dict-mini.txt"

int dictLength = 0;
int dataLength = 0;
char lastCrackedPassword[33];
int lastCrackedIndex;
char **dict;
int consumerCounter = 0;

pthread_mutex_t toogleMutex;
pthread_cond_t cond;
pthread_mutex_t condMutex;

struct Data
{
	char *hash;
	char *email;
};

struct Data *dataInfo;

void loadDict()
{
	char *temp = (char *)malloc(BUF_SIZE * sizeof(char));
	dict = (char **)malloc(DICT_SIZE * sizeof(char *));
	for (int i = 0; i < DICT_SIZE; i++)
	{
		dict[i] = (char *)malloc(BUF_SIZE * sizeof(char));
	}
	FILE *dictFile = fopen(DICT_FILE, "r");
	if (!dictFile)
	{
		printf("Cannot load dictionary\n");
	}
	int i = 0;
	while (fscanf(dictFile, "%s", temp) > 0)
	{
		strcpy(dict[i++], temp);
		dictLength++;
	}
	printf("Dictionary has been loaded correctly\n");
	free(temp);
}

void loadData(char *dataToLoad)
{
	dataInfo = (struct Data *)malloc(BUF_SIZE * sizeof(struct Data));
	char *temp = (char *)malloc(BUF_SIZE * sizeof(char));
	char *tempHash = (char *)malloc(BUF_SIZE * sizeof(char));
	char *tempMail = (char *)malloc(BUF_SIZE * sizeof(char));
	char *temp4 = (char *)malloc(BUF_SIZE * sizeof(char));

	FILE *dataFile = fopen(dataToLoad, "r");
	if (!dataFile)
	{
		printf("Cannot load data\n");
	}
	int i = 0;
	while (fscanf(dataFile, "%s %s %s %s", temp, tempHash, tempMail, temp4) == 4)
	{
		dataInfo[i].hash = (char *)malloc(BUF_SIZE * sizeof(char));
		strcpy(dataInfo[i].hash, tempHash);

		dataInfo[i].email = (char *)malloc(BUF_SIZE * sizeof(char));
		strcpy(dataInfo[i].email, tempMail);
		i++;
		dataLength++;
	}
	printf("Data has been loaded correctly\n");
	free(temp);
	free(tempHash);
	free(tempMail);
	free(temp4);
}

void bytes2md5(const char *data, int len, char *md5buf)
{
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	const EVP_MD *md = EVP_md5();
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len, i;
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, data, len);
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_free(mdctx);
	for (i = 0; i < md_len; i++)
	{
		snprintf(&(md5buf[i * 2]), 16 * 2, "%02x", md_value[i]);
	}
}

void comparePasses(char *wordToCrack, int dataCounter)
{
	char md5[33];
	bytes2md5(wordToCrack, strlen(wordToCrack), md5);
	if (strcmp(md5, dataInfo[dataCounter].hash) == 0)
	{
		pthread_mutex_lock(&toogleMutex);
		dataInfo[dataCounter].hash[0] = '\0';

		consumerCounter = dataCounter;
		strcpy(lastCrackedPassword, wordToCrack);
		pthread_cond_signal(&cond);
		pthread_mutex_unlock(&toogleMutex);
	}
}

void checkWithPostfix(char *word, int bool)
{
	for (int i = 0; i < 10; i++)
	{
		char *temp = (char *)malloc(2 * sizeof(char));
		char *tempCrack = (char *)malloc(BUF_SIZE * sizeof(char));
		strcpy(tempCrack, word);
		sprintf(temp, "%d", i);
		strcat(tempCrack, temp);
		for (int j = 0; j < dataLength; j++)
		{
			comparePasses(tempCrack, j);
		}
		if (bool != 0)
			checkWithPostfix(tempCrack, 0);
		free(temp);
		free(tempCrack);
	}
}

void checkWithPrefix(char *word, int bool)
{
	for (int i = 0; i < 10; i++)
	{
		char *temp = (char *)malloc(2 * sizeof(char));
		char *tempCrack = (char *)malloc(BUF_SIZE * sizeof(char));
		sprintf(temp, "%d", i);
		strcpy(tempCrack, temp);
		strcat(tempCrack, word);
		for (int j = 0; j < dataLength; j++)
		{
			comparePasses(tempCrack, j);
		}
		if (bool != 0)
			checkWithPrefix(tempCrack, 0);
		free(temp);
		free(tempCrack);
	}
}

void stringToUpper(char *temp)
{
	char *s = temp;
	while (*s)
	{
		*s = toupper((char)*s);
		s++;
	}
}

void firstCharToUpper(char *temp)
{
	char *s = temp;
	*s = toupper((char)*s);
}

void crackWord(char *tmpWord)
{

	for (int j = 0; j < dataLength; j++)
	{
		comparePasses(tmpWord, j);
	}
	checkWithPrefix(tmpWord, 1);
	checkWithPostfix(tmpWord, 1);
}

void *producent0()
{
	for (int i = 0; i < dictLength; i++)
	{
		char *tempWord = (char *)malloc(BUF_SIZE * sizeof(char));
		strcpy(tempWord, dict[i]);
		crackWord(tempWord);
		free(tempWord);
	}
	pthread_exit(NULL);
}

void *producent1()
{
	for (int i = 0; i < dictLength; i++)
	{
		char *tempWord = (char *)malloc(BUF_SIZE * sizeof(char));
		strcpy(tempWord, dict[i]);
		firstCharToUpper(tempWord);
		crackWord(tempWord);
		free(tempWord);
	}

	pthread_exit(NULL);
}

void *producent2()
{
	for (int i = 0; i < dictLength; i++)
	{
		char *tempWord = (char *)malloc(BUF_SIZE * sizeof(char));
		strcpy(tempWord, dict[i]);
		stringToUpper(tempWord);
		crackWord(tempWord);
		free(tempWord);
	}

	pthread_exit(NULL);
}

void *producent0double()
{
	char *tempWord = (char *)malloc(BUF_SIZE * sizeof(char));
	char *tempWord2 = (char *)malloc(BUF_SIZE * sizeof(char));
	char *spacja = (char *)malloc(3 * sizeof(char));
	strcpy(spacja, " ");

	for (int j = 0; j < dictLength; j++)
	{
		for (int i = 0; i < dictLength; i++)
		{
			strcpy(tempWord, dict[i]);
			strcat(tempWord, spacja);
			strcpy(tempWord2, tempWord);
			strcat(tempWord2, dict[j]);
			crackWord(tempWord2);
		}
	}
	free(tempWord);
	free(tempWord2);
	free(spacja);
	pthread_exit(NULL);
}

void *producent1double()
{
	for (int j = 0; j < dictLength; j++)
	{
		for (int i = 0; i < dictLength; i++)
		{
			char *tempWord = (char *)malloc(BUF_SIZE * sizeof(char));
			char *tempWord2 = (char *)malloc(BUF_SIZE * sizeof(char));
			strcpy(tempWord, dict[i]);
			firstCharToUpper(tempWord);
			strcpy(tempWord2, dict[j]);
			firstCharToUpper(tempWord2);
			strcat(tempWord, tempWord2);
			crackWord(tempWord);
			free(tempWord);
			free(tempWord2);
		}
	}

	pthread_exit(NULL);
}

void *producent2double()
{
	for (int j = 0; j < dictLength; j++)
	{
		for (int i = 0; i < dictLength; i++)
		{
			char *tempWord = (char *)malloc(BUF_SIZE * sizeof(char));
			char *tempWord2 = (char *)malloc(BUF_SIZE * sizeof(char));
			strcpy(tempWord, dict[i]);
			firstCharToUpper(tempWord);
			strcpy(tempWord2, dict[j]);
			firstCharToUpper(tempWord2);
			strcat(tempWord, tempWord2);
			crackWord(tempWord);
			free(tempWord);
			free(tempWord2);
		}
	}

	pthread_exit(NULL);
}

void *consumer()
{
	while (1)
	{
		pthread_mutex_lock(&condMutex);
		pthread_cond_wait(&cond, &condMutex);
		printf("Password for: %s is: %s.\n", dataInfo[consumerCounter].email, lastCrackedPassword);
		pthread_mutex_unlock(&condMutex);
	}
	pthread_exit(NULL);
}

void *createThreads()
{
	pthread_t thread0, thread1, thread2, thread0double, thread1double, thread2double, threadConsumer;
	pthread_create(&thread0, NULL, producent0, NULL);
	pthread_create(&thread1, NULL, producent1, NULL);
	pthread_create(&thread2, NULL, producent2, NULL);
	pthread_create(&thread0double, NULL, producent0double, NULL);
	pthread_create(&thread1double, NULL, producent1double, NULL);
	pthread_create(&thread2double, NULL, producent2double, NULL);
	pthread_create(&threadConsumer, NULL, consumer, NULL);
}

void main()
{
	char *dataTMP = (char *)malloc(20 * sizeof(char));

	loadDict();
	printf("Type file that you want to load:\n");
	scanf("%s", dataTMP);
	loadData(dataTMP);

	pthread_mutex_lock(&condMutex);
	pthread_mutex_init(&toogleMutex, NULL);
	pthread_mutex_init(&condMutex, NULL);
	pthread_cond_init(&cond, NULL);
	pthread_t main;
	pthread_create(&main, NULL, createThreads, NULL);
	pthread_exit(NULL);
	free(dataTMP);
}
