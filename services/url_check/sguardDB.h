#ifndef __SGUARDDB_H
#include <db.h>

typedef struct sg_db{
  DB_ENV *env_db;
  DB *domains_db;
  DB *urls_db;
} sg_db_t;


sg_db_t *sg_init_db(char *home);
void sg_close_db(sg_db_t *sg_db);
int sg_domain_exists(sg_db_t *sg_db, char *domain);
int sg_url_exists(sg_db_t *sg_db, char *url);


#endif
