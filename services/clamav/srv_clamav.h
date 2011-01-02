#ifndef __SRV_CLAMAV_H
#define __SRV_CLAMAV_H

#include "body.h"
#include "request.h"

#define VIRALATOR_MODE

#define LOG_URL_SIZE 256
typedef struct av_req_data{
     ci_simple_file_t *body;
     ci_request_t *req;
     int must_scanned ;
     int allow204;
     int virus_check_done;
     char *virus_name;
     ci_membuf_t *error_page;
     char url_log[LOG_URL_SIZE];
#ifdef VIRALATOR_MODE
     time_t last_update;
     char *requested_filename;
     int vir_mode_state;
#endif
     ci_off_t expected_size;
     struct{
	  int enable204;
	  int forcescan;
	  int sizelimit;
	  int mode;
     } args;
     ci_off_t max_object_size;
     int send_percent_bytes;
     ci_off_t start_send_after;
}av_req_data_t;

enum {NO_SCAN=0,SCAN,VIR_SCAN};

#ifdef VIRALATOR_MODE

enum {VIR_ZERO, VIR_HEAD, VIR_MAIN, VIR_TAIL, VIR_END};

void init_vir_mode_data(ci_request_t *req,av_req_data_t *data);
int send_vir_mode_page(av_req_data_t *data,char *buf,int len,ci_request_t *req);
void endof_data_vir_mode(av_req_data_t *data,ci_request_t *req);
#endif

/*Clamav support functions*/
int clamav_init();
char *clamav_scan(int fd, unsigned long *scanned_data);
void clamav_get_versions(unsigned int *level, unsigned int *version, char *str, size_t len);
int clamav_init_virusdb();
int clamav_reload_virusdb();
void clamav_destroy_virusdb();


#endif
