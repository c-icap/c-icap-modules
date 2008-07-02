#ifndef __SGUARDDB_H

int initDB(int  create);
void closeDB();
int DomainExists(char *domain);
int iterateDomains(int (*action)(char *,int,char *,int));

#endif
