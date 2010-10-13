struct aaa {
	char a;
	char b;
	char c;
	char d;
};

struct arghfoo {
	char a;
	char b;
	char c;
	int d;
	int e;
	int f;
	long int g;
	struct arghfoo* h;
};

typedef struct {
	int i;
	int* j;
	char* n;
	long f;
} barfoo;

int glob_arg;

int glue(barfoo* a);
int bla(barfoo* b, struct arghfoo* aaaaa);
int bla2(char* b, int g);
int haha(char* a, char c);
