#include<stdio.h>
#include<stdlib.h> 
#include<string.h> 
#include<time.h>
#include<stdint.h>
#include<math.h>

typedef struct account
{
	int acc_no;
	int balance;
	int pin;
	char name[20];
    struct account* next;
}node_t;

node_t *head;
node_t *tmp;


struct public_key_class{
  long long modulus;
  long long exponent;
};

struct private_key_class{
  long long modulus;
  long long exponent;
};

char *PRIME_SOURCE_FILE = "primes.txt";
char buffer[1024];
//const int MAX_DIGITS = 50;
int i,j = 0;

// This should totally be in the math library.
long long gcd(long long a, long long b)
{
  long long c;
  while ( a != 0 ) {
    c = a; a = b%a;  b = c;
  }
  return b;
}


long long ExtEuclid(long long a, long long b)
{
 long long x = 0, y = 1, u = 1, v = 0, gcd = b, m, n, q, r;
 while (a!=0) {
   q = gcd/a; r = gcd % a;
   m = x-u*q; n = y-v*q;
   gcd = a; a = r; x = u; y = v; u = m; v = n;
   }
   return y;
}

long long rsa_modExp(long long b, long long e, long long m)
{
  if (b < 0 || e < 0 || m <= 0){
    exit(1);
  }
  b = b % m;
  if(e == 0) return 1;
  if(e == 1) return b;
  if( e % 2 == 0){
    return ( rsa_modExp(b * b % m, e/2, m) % m );
  }
  if( e % 2 == 1){
    return ( b * rsa_modExp(b, (e-1), m) % m );
  }

}

 
void rsa_gen_keys(struct public_key_class *pub, struct private_key_class *priv, char *PRIME_SOURCE_FILE)
{
  

  long long p = 0;
  long long q = 0;

  long long e = powl(2, 8) + 1;
  long long d = 0;
  long long max = 0;
  long long phi_max = 0;
  
  
    p = 89963; 
    q = 32887; 

    max = p*q;
    phi_max = (p-1)*(q-1);
 
  // Next, we need to choose a,b, so that a*max+b*e = gcd(max,e). We actually only need b
  // here, and in keeping with the usual notation of RSA we'll call it d. We'd also like 
  // to make sure we get a representation of d as positive, hence the while loop.
  d = ExtEuclid(phi_max,e);
  while(d < 0)
  {
    d = d+phi_max;
  }

  //printf("primes are %lld and %lld\n",(long long)p, (long long )q);
  // We now store the public / private keys in the appropriate structs
  pub->modulus = max;
  pub->exponent = e;

  priv->modulus = max;
  priv->exponent = d;
}


long long *rsa_encrypt(const char *message, const unsigned long message_size, 
                     const struct public_key_class *pub)
{
  long long *encrypted = malloc(sizeof(long long)*message_size);
  if(encrypted == NULL){
    fprintf(stderr,
     "Error: Heap allocation failed.\n");
    return NULL;
  }
  long long i = 0;
  for(i=0; i < message_size; i++){
    encrypted[i] = rsa_modExp(message[i], pub->exponent, pub->modulus);
  }
  return encrypted;
}


char *rsa_decrypt(const long long *message, 
                  const unsigned long message_size, 
                  const struct private_key_class *priv)
{
  if(message_size % sizeof(long long) != 0){
    fprintf(stderr,
     "Error: message_size is not divisible by %d, so cannot be output of rsa_encrypt\n", (int)sizeof(long long));
     return NULL;
  }
  // We allocate space to do the decryption (temp) and space for the output as a char array
  // (decrypted)
  char *decrypted = malloc(message_size/sizeof(long long));
  char *temp = malloc(message_size);
  if((decrypted == NULL) || (temp == NULL)){
    fprintf(stderr,
     "Error: Heap allocation failed.\n");
    return NULL;
  }
  // Now we go through each 8-byte chunk and decrypt it.
  long long i = 0;
  for(i=0; i < message_size/8; i++){
    temp[i] = rsa_modExp(message[i], priv->exponent, priv->modulus);
  }
  // The result should be a number in the char range, which gives back the original byte.
  // We put that into decrypted, then return.
  for(i=0; i < message_size/8; i++){
    decrypted[i] = temp[i];
  }
  free(temp);
  return decrypted;
}




int encrypt()
{
	struct public_key_class pub[1];
	struct private_key_class priv[1];
	rsa_gen_keys(pub, priv, PRIME_SOURCE_FILE);

	//printf("Private Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)priv->modulus, (long long) priv->exponent);
	//printf("Public Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)pub->modulus, (long long) pub->exponent);
	int i;
  
	FILE* fp=fopen("banking.csv","r");
	if(!fp)
		printf("Error in opening file");
  
	int count=0;
  
    for(char ch=getc(fp); ch!=EOF; ch=getc(fp))
		++count;
  
    char message[count];
  
    rewind(fp);
  
    for(i=0 ; i<count ; ++i)
    {
		char c=getc(fp);
		message[i] = c;
    }
    fclose(fp);
 
  
    long long *encrypted = rsa_encrypt(message, sizeof(message), pub);
    if (!encrypted)
	{
		fprintf(stderr, "Error in encryption!\n");
		return 1;
    }
  
  
    FILE* fptOut=fopen("enc.txt","w");
    if(!fptOut)
		printf("Error in opening file");

    printf("Encrypted\n");
    for(i=0; i < strlen(message); i++)
	{
		fprintf(fptOut, "%lld\n", (long long)encrypted[i]);
    }
    fclose(fptOut);
  
    free(encrypted);
	FILE* fpd=fopen("banking.csv","w");
	fclose(fpd);
}





int decrypt()
{
	struct public_key_class pub[1];
	struct private_key_class priv[1];
	rsa_gen_keys(pub, priv, PRIME_SOURCE_FILE);

	//printf("Private Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)priv->modulus, (long long) priv->exponent);
	//printf("Public Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)pub->modulus, (long long) pub->exponent);
	int i;
	FILE* fptIn=fopen("enc.txt","r");
    if(!fptIn)
		printf("Error in opening file");
    char line[1024];
	int lc=0;
	for(char c=getc(fptIn); c!=EOF; c=getc(fptIn))
	{
		if(c=='\n')
			++lc;
	}
	
	long long msg[lc];
	rewind(fptIn);
	int o=0;
	while(fgets(line,1024,(FILE*)fptIn) && o < lc)
	{
		msg[o]=0;
		for(i=0; i < strlen(line); i++)
		{
			if(line[i]!='\n')
				msg[o]=msg[o]*10+((int)line[i]-48);
		}
		++o;
	}
    fclose(fptIn);
    char *decrypted = rsa_decrypt(msg, 8*lc, priv);
    if (!decrypted)
	{
		fprintf(stderr, "Error in decryption!\n");
		return 1;
    }
  
    FILE* fpd=fopen("banking.csv","w");
    if(!fpd)
		printf("Error in opening file");
    for(i=0; i < lc; i++)
	{
		long long hi = (long long)decrypted[i];
		char chi = (char)hi;
		fputc(chi,fpd);
    }
    fclose(fpd);
	
	free(decrypted);
}






long int acc_num()
{
	srand(time(NULL));
	long int num = (rand() % (999999 - 100000 + 1)) + 100000;
	return num;
}

int pin_num()
{	srand(time(NULL));
	long int num = (rand() % (9999 - 1000 + 1)) + 1000;
	return num;
}


int check_account(int ac, int pn)
{
	tmp=(node_t*)malloc(sizeof(node_t));
	tmp=head;
	while (tmp != NULL) 
	{
		if(tmp->acc_no == ac)
		{
			if(tmp->pin == pn)
				return 1;
			else
				tmp = tmp->next; 
		}
	}
	return 0;
}

void balance_enquiry(int ac)
{
	if(tmp->acc_no == ac)
			printf("\nBalance is : %d",tmp->balance);
}


int print_details(int an)
{
    printf("Account no : %d",tmp->acc_no);
    printf("\nName : %s",tmp->name);
    printf("\nBalance : %d",tmp->balance);
	printf("\nPin : %d",tmp->pin);
}

void add_to_file()
{   
    FILE* fp1=fopen("banking.csv","w");
    if(!fp1)
        printf("Error in opening file");
    while(head!=NULL)
    {
        fprintf(fp1,"%d,%d,%d,%s\n",head->acc_no,head->balance,head->pin,head->name);
        head=head->next;
    }
    fclose(fp1);
}

void read_from_file()
{
    
    FILE* fp=fopen("banking.csv","r");
    if(!fp)
        printf("Error in opening file");
	char line[1024];
	int lc=0;
	for(char c=getc(fp); c!=EOF; c=getc(fp))
	{
		if(c=='\n')
			++lc;
	}
	
	rewind(fp);
	int i=0;
	node_t *temp=(node_t*)malloc(sizeof(node_t));
	while(fgets(line,1024,(FILE*)fp) && i < lc)
	{
		
		temp->acc_no = atoi(strtok(line, ","));
		temp->balance=atoi(strtok(NULL, ","));
		temp->pin = atoi(strtok(NULL, ","));
		strcpy(temp->name,strtok(NULL, "\n"));
		temp->next=NULL;
		
		
		if(head==NULL)
		{head=temp;}
		
		else
		{
			temp->next=head;
			head=temp;	
		}
		
		i++;
		temp=NULL;
		temp=(node_t*)malloc(sizeof(node_t));
    }
	free(temp);
	fclose(fp);
}

int w_money()
{
	int p,amt;
	printf("Enter Pin : ");
	scanf("%d",&p);
	system("clear");
	if(tmp->pin == p)
	{
		printf("\nEnter amount to withdraw : ");
		scanf("%d",&amt);
		if(amt<tmp->balance)
		{
			tmp->balance-=amt;
					printf("\nAmount of %d withdrawn",amt);
		}
		else
			printf("\nINSUFFICIENT BALANCE!!");	
	}
	else
		printf("\nWRONG PIN!!");
}

int d_money()
{
	int amt;
	printf("Enter amount to deposit : ");
	scanf("%d",&amt);
	tmp->balance+=amt;
	printf("\nAmount of %d deposited",amt);
}

int add_account()
{
    char n[50];int b;
    node_t *temp=(node_t*)malloc(sizeof(node_t));
	temp->acc_no=acc_num();
    printf("\nAccount no : %d",temp->acc_no);
    printf("\nEnter name : ");
	fflush(stdin);
    scanf("%s",n);
	strcpy(temp->name,n);
    printf("Enter Amount depositing : ");
    scanf("%d",&b);
    temp->balance=b;
    temp->pin=pin_num();
    printf("PIN : %d",temp->pin);
	temp->next=NULL;
	if(head==NULL)
		{head=temp;}
	else{
		temp->next=head;
		head=temp;
	}
}



int main()
{
    head=NULL;
    decrypt();
    read_from_file();
    char ch;	
    system("clear");
    printf("\t\t\t\t\t\t\tWELCOME TO DEUTSCHE BANK\n");
    printf("Do have an account(y/n) : ");
    scanf("%c",&ch);
    fflush(stdin);
    system("clear");
    if(ch=='n')
    {
        printf("ACCOUNT CREATION");
        add_account();
	printf("\n\n\n");
    }
	printf("Enter account number : ");
	int y;
	scanf("%d",&y);
	printf("Enter pin : ");
	int z;
	scanf("%d",&z);
	int x = 0;
	x = check_account(y,z);
	system("clear");
	if(x==1)
	{	
		
		int flag=1;
		while(flag)
		{	printf("\n\n\n");
			printf("1. Print Details\n");
			printf("2. Balance inquiry\n");
			printf("3. Withdraw money\n");
			printf("4. Deposit money\n");
			printf("5. Exit\n");
			printf("Enter choice : ");
			int choice;
			scanf("%d",&choice);
		
			switch(choice)
			{
				case 1:
				system("clear");
				print_details(y);
				break;

				case 2:
				system("clear");
				balance_enquiry(y);
				break;

				case 3:
				system("clear");
				w_money(y);
				break;

				case 4:
				system("clear");
				d_money(y);
				break;

				case 5:
				system("clear");
                flag=0;
				break;

				
				default:
				system("clear");
				printf("Invalid choice\n");
				break;
			}
		}
	}


	else
		printf("Invalid account number or password\n");

	add_to_file();
	encrypt();
	return 0;
}