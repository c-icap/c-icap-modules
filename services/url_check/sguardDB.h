#ifndef __SGUARDDB_H

typedef enum sgQueryType {sgDomain, sgUrl} sgQueryType;
enum sgDBopen {sgDBreadonly, sgDBupdate, sgDBrebuild};

typedef struct sg_db_type {
    void *(*init_db)(const char *home, enum sgDBopen otype);
    void (*close_db)(void *data);
    int (*entry_exists)(void *data, sgQueryType type, char *entry,int (*cmpkey)(const char *,const char *,int ));
    int (*entry_add)(void *data, sgQueryType type, char *entry);
    int (*entry_remove)(void *data, sgQueryType type, char *entry);
    int (*iterate)(void *data, sgQueryType type, int (*action)(const char *, int, const char *,int));
    void (*start_modify)(void *data);
    void (*stop_modify)(void *data);
    const char *name;
} sg_db_type_t;

typedef struct sg_db{
    char *db_home;
    char *domains_db_name;
    char *urls_db_name;
    void *data;
    const sg_db_type_t *db_type;
} sg_db_t;

sg_db_t *sg_init_db(const char *name, const char *home, enum sgDBopen type);
void sg_close_db(sg_db_t *sg_db);
int sg_domain_exists(sg_db_t *sg_db, char *domain);
int sg_url_exists(sg_db_t *sg_db, char *url);


#endif
