#include <gtk/gtk.h>
#include<stdio.h>
#include<stdlib.h> 
#include<string.h> 
#include<time.h>
#include<stdint.h>
#include<math.h>
#include<stdbool.h>

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
		}
		tmp = tmp->next; 
	}
	return 0;
}

void balance_enquiry(int ac)
{
	if(tmp->acc_no == ac)
			printf("\nBalance is:%d",tmp->balance);
		tmp = tmp->next;
}


int print_details(int an)
{
    printf("\nAccount no:%d",tmp->acc_no);
    printf("\nName:%s",tmp->name);
    printf("\nBalance:%d",tmp->balance);
	printf("\nPin:%d",tmp->pin);
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





int add_account()
{
    char n[50];int b;
    node_t *temp=(node_t*)malloc(sizeof(node_t));
	temp->acc_no=acc_num();
    printf("\nAccount no:%d",temp->acc_no);
    printf("\nEnter name:");
	fflush(stdin);
    scanf("%s",n);
	strcpy(temp->name,n);
    printf("Enter Amount depositing:");
    scanf("%d",&b);
    temp->balance=b;
    temp->pin=pin_num();
    printf("PIN:%d",temp->pin);
	temp->next=NULL;
	if(head==NULL)
		{head=temp;}
	else{
		temp->next=head;
		head=temp;
	}
}



void print_w (GtkWidget *widget, GtkEntry *amount)
{
    GtkWidget *win,*label;
    win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(win), 90, 50);
    gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);
    const gchar* ty = gtk_entry_get_text(amount);
    char* tm = (char*)ty;
    int r = atoi(tm);
  if(r<tmp->balance){
  label = gtk_label_new("Amount Withdrawn!");
  gtk_container_add(GTK_CONTAINER(win), label);
  tmp->balance = tmp->balance - r; }
   else  {
  label = gtk_label_new("INSUFFICIENT BALANCE!!");
  gtk_container_add(GTK_CONTAINER(win), label);  }
  gtk_widget_show_all(win);

}
   

void print_d (GtkWidget *widget, GtkEntry *amount)
{
    GtkWidget *win,*label;
    win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(win), 75, 50);
    gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);
    
    const gchar* ty = gtk_entry_get_text(amount);
    char* tm = (char*)ty;
    int r = atoi(tm);
  label = gtk_label_new("Amount Deposited!");
  gtk_container_add(GTK_CONTAINER(win), label);
  tmp->balance = tmp->balance + r;
  gtk_widget_show_all(win); 
   }


void inq(GtkWidget *button, gpointer *data) {
GtkWidget *win,*label,*label1, *grid;
    grid = gtk_grid_new();
    //gtk_grid_set_row_spacing(GTK_GRID(grid), 100);
    win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_container_add(GTK_CONTAINER(win), grid);
    gtk_window_set_default_size(GTK_WINDOW(win), 150, 50);
    gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);
    label = gtk_label_new("Your current balance is");
    gtk_grid_attach(GTK_GRID(grid), label, 0, 0, 1, 1);
    char tfu[20];
    snprintf(tfu, sizeof(tfu), "%d", tmp->balance);
    const gchar* trw = (gchar*)tfu;
    label1 = gtk_label_new(trw);
    gtk_grid_attach(GTK_GRID(grid), label1, 2, 0, 1, 1);
    gtk_widget_show_all(win);

}    

void exit1(GtkWidget *button, gpointer *data) {
g_print("Thank you for using Deutsche Bank. Have a great day.\n"); 
gtk_main_quit(); }


void create_detail(GtkWidget *button, gpointer *data) {
    GtkWidget *win, *name, *acc, *pin, *grid, *label1, *label2, *label3;
    
    win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(win), "Details");
    gtk_window_set_default_size(GTK_WINDOW(win), 150, 150);
    gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);
    gtk_container_set_border_width(GTK_CONTAINER(win), 20);
    gtk_window_set_resizable(GTK_WINDOW(win), TRUE);    
    grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 25);
    
    gtk_container_add(GTK_CONTAINER(win), grid);
    
    label1 = gtk_label_new("Name: ");
    gtk_grid_attach(GTK_GRID(grid), label1, 0, 0, 1, 1);
    const gchar* t = (gchar*)tmp->name;
    name = gtk_label_new(t);
    gtk_grid_attach(GTK_GRID(grid), name, 1, 0, 1, 1);

    label2 = gtk_label_new("A/C No: ");
    gtk_grid_attach(GTK_GRID(grid), label2, 0, 1, 1, 1);
    char tfu[20];
    snprintf(tfu, sizeof(tfu), "%d", tmp->acc_no);
    const gchar* trw = (gchar*)tfu;
    acc = gtk_label_new(trw);
    gtk_grid_attach(GTK_GRID(grid), acc, 1, 1, 1, 1);

    label3 = gtk_label_new("PIN: ");
    gtk_grid_attach(GTK_GRID(grid), label3, 0, 2, 1, 1);
    char tfue[20];
    snprintf(tfue, sizeof(tfue), "%d", tmp->pin);
    const gchar* trwq = (gchar*)tfue;
    pin = gtk_label_new(trwq);
    gtk_grid_attach(GTK_GRID(grid), pin, 1, 2, 1, 1);

gtk_widget_show_all(win);

}


void create_withdraw(GtkWidget *button, gpointer window) 
{
	GtkWidget *amount, *label, *grid, *win, *butt;
    win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(win), "Withdraw");
    gtk_window_set_default_size(GTK_WINDOW(win), 200, 200);
    gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);
    gtk_container_set_border_width(GTK_CONTAINER(win), 30);
    gtk_window_set_resizable(GTK_WINDOW(win), TRUE);    
    grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    
    gtk_container_add(GTK_CONTAINER(win), grid);
    
    label = gtk_label_new("Please enter amount you would like and press Enter");
    gtk_label_set_xalign (GTK_LABEL(label), 0.4);
    gtk_label_set_yalign (GTK_LABEL(label), 0.4);
    gtk_grid_attach(GTK_GRID(grid), label, 1, 0, 1, 1);
    amount = gtk_entry_new();
    gtk_grid_attach(GTK_GRID(grid), amount, 1, 2, 1, 1);
    butt = gtk_button_new_with_label("Enter");
    
    gtk_grid_attach(GTK_GRID(grid), butt, 1, 3, 1, 1);

    	g_signal_connect(butt, "clicked", G_CALLBACK(print_w), amount);
     
    gtk_widget_show_all(win);

}
 

void create_deposit(GtkWidget *button, gpointer window) {

    GtkWidget *amount, *label, *grid, *win, *butt;
    win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(win), "Deposit");
    gtk_window_set_default_size(GTK_WINDOW(win), 200, 200);
    gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);
    gtk_container_set_border_width(GTK_CONTAINER(win), 30);
    gtk_window_set_resizable(GTK_WINDOW(win), TRUE);    
    grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    
    gtk_container_add(GTK_CONTAINER(win), grid);
    
    label = gtk_label_new("Please enter amount you would like and press Enter");
    gtk_label_set_xalign (GTK_LABEL(label), 0.4);
    gtk_label_set_yalign (GTK_LABEL(label), 0.4);
    gtk_grid_attach(GTK_GRID(grid), label, 1, 0, 1, 1);
    amount = gtk_entry_new();
    gtk_grid_attach(GTK_GRID(grid), amount, 1, 2, 1, 1);
    butt = gtk_button_new_with_label("Enter");
    
    gtk_grid_attach(GTK_GRID(grid), butt, 1, 3, 1, 1);
    g_signal_connect(butt, "clicked", G_CALLBACK(print_d), amount);
    gtk_widget_show_all(win);
}
    

GtkWidget *u_name;
GtkWidget *pass;


void bank_window(GtkWidget *button, gpointer window) {

	tmp = head;
    GtkEntry *e = (GtkEntry*)u_name;
    const gchar* f = gtk_entry_get_text(e);
    char *acc = (char*)f;
    int r = atoi(acc);

    GtkEntry *x = (GtkEntry*)pass;
    const gchar* y = gtk_entry_get_text(x);
    char *pin1 = (char*)y;
    int r1 = atoi(pin1);

    
    GtkWidget *win, *label, *grid, *label2, *label3, *label4;
    GtkWidget *detail, *balance, *withdraw, *deposit, *exit;
    GtkWidget *image;
    
    if(check_account(r,r1)) {   

    image = gtk_image_new_from_file ("download.jpeg");
    
    label = gtk_label_new("Willkommen zu Deutsche Bank");  
    label2 = gtk_label_new("*All rights reserved to Deutsche Bank.");
    label3 = gtk_label_new("Dear Customer");
    label4 = gtk_label_new("Please select operation");
    win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(win), "Welcome to Deutsche Bank");
    gtk_window_set_default_size(GTK_WINDOW(win), 300, 300);
    
    gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);
    gtk_container_set_border_width(GTK_CONTAINER(win), 30);
    gtk_window_set_resizable(GTK_WINDOW(win), TRUE);    
    grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 5);
    
    gtk_container_add(GTK_CONTAINER(win), grid);

    gtk_grid_attach(GTK_GRID(grid), image, -1, 0, 1, 1);

    gtk_grid_attach(GTK_GRID(grid), label, 3, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), label3, 3, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), label4, 3, 2, 1, 1);

    detail = gtk_button_new_with_label("Print Details");
    g_signal_connect(detail, "clicked", G_CALLBACK(create_detail), NULL);
    gtk_grid_attach(GTK_GRID(grid), detail, 0, 2, 3, 3);
    
    balance = gtk_button_new_with_label("Balance Enquiry");
    g_signal_connect(balance, "clicked", G_CALLBACK(inq), NULL);
    gtk_grid_attach(GTK_GRID(grid), balance, 0, 5, 3, 3);
    
    withdraw = gtk_button_new_with_label("Withdraw Money");
    g_signal_connect(withdraw, "clicked", G_CALLBACK(create_withdraw), NULL);
    gtk_grid_attach(GTK_GRID(grid), withdraw, 5, 2, 3, 3);
    
    deposit = gtk_button_new_with_label("Deposit Money");
    g_signal_connect(deposit, "clicked", G_CALLBACK(create_deposit), NULL);
    gtk_grid_attach(GTK_GRID(grid), deposit, 5, 5, 3, 3);
 
    exit = gtk_button_new_with_label("Exit");
    g_signal_connect(exit, "clicked", G_CALLBACK(exit1), NULL);
    gtk_grid_attach(GTK_GRID(grid), exit, 25, 30, 3, 3);
    // row, columns, width, height
    gtk_grid_attach(GTK_GRID(grid), label2, -1, 30, 1, 1);   }

    else 
	g_print("Please try again\n");
	


    gtk_widget_show_all(win);

}


void login_window(GtkWidget *widget, gpointer data) {

GtkWidget *window;
GtkWidget *grid;
GtkWidget *Login_button, *Quit_button;

GtkWidget *label_user;
GtkWidget *label_pass;
GtkWidget  *button_container;

window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
gtk_window_set_title(GTK_WINDOW(window), "Gateway");
gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
gtk_container_set_border_width(GTK_CONTAINER(window), 10);
gtk_window_set_resizable(GTK_WINDOW(window), FALSE); 

grid = gtk_grid_new();
gtk_grid_set_row_spacing(GTK_GRID(grid), 3);
gtk_container_add(GTK_CONTAINER(window), grid);

label_user = gtk_label_new("Username  ");
label_pass = gtk_label_new("Key  ");

u_name = gtk_entry_new();
gtk_entry_set_placeholder_text(GTK_ENTRY(u_name), "Username");
gtk_grid_attach(GTK_GRID(grid), label_user, 0, 1, 1, 1);
gtk_grid_attach(GTK_GRID(grid), u_name, 1, 1, 2, 1);

pass = gtk_entry_new();
gtk_entry_set_placeholder_text(GTK_ENTRY(pass), "Key");
gtk_grid_attach(GTK_GRID(grid), label_pass, 0, 2, 1, 1);
gtk_entry_set_visibility(GTK_ENTRY(pass), 0);
gtk_grid_attach(GTK_GRID(grid), pass, 1, 2, 1, 1);

Login_button = gtk_button_new_with_label("Log in");
g_signal_connect(Login_button, "clicked", G_CALLBACK(bank_window), NULL);
gtk_grid_attach(GTK_GRID(grid), Login_button, 0, 3, 2, 1);

Quit_button = gtk_button_new_with_label("Quit");
g_signal_connect(Quit_button, "clicked", G_CALLBACK(exit1), NULL);
gtk_grid_attach(GTK_GRID(grid), Quit_button, 0, 4, 2, 1);

gtk_widget_show_all(window);

gtk_main();
}




int main(int argc, char *argv[]){


head=NULL;
	decrypt();
    read_from_file();


gtk_init(&argc, &argv);
GtkWidget *win, *label, *grid, *yes, *no;

win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
gtk_window_set_title(GTK_WINDOW(win), "Deutsche Bank Portal");
gtk_window_set_default_size(GTK_WINDOW(win), 100, 100);
    
gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);
gtk_container_set_border_width(GTK_CONTAINER(win), 20);
gtk_window_set_resizable(GTK_WINDOW(win), TRUE);    

grid = gtk_grid_new();
gtk_grid_set_column_spacing(GTK_GRID(grid), 5);
gtk_container_add(GTK_CONTAINER(win), grid);

label = gtk_label_new("Do you have an existing account?");
gtk_grid_attach(GTK_GRID(grid), label, 0, -1, 1, 1);

yes = gtk_button_new_with_label("Yes");
g_signal_connect(yes, "clicked", G_CALLBACK(login_window), NULL);
gtk_grid_attach(GTK_GRID(grid), yes, 0, 1, 1, 1);

no = gtk_button_new_with_label("No");
g_signal_connect(no, "clicked", G_CALLBACK(add_account), NULL);
gtk_grid_attach(GTK_GRID(grid), no, 0, 2, 1, 1);

gtk_widget_show_all(win);


gtk_main();

add_to_file();
encrypt();

return 0;
}