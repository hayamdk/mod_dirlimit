#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_global_mutex.h"
#include "apr_tables.h"
#include "unixd.h"

#define MAX_CLIENTS 2048
#define MAX_DIRNAME 32

#define USER_DATA_KEY "mod_dirlimit_key"
#define DIRNAME_INFO_KEY "mod_dirlimit_dirname"
#define MUTEX_PATH NULL
#define SHM_PATH NULL

//#define DEBUGLOG(...) ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, NULL, __VA_ARGS__)
#define DEBUGLOG(...)
#define ERRORLOG(...) ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, __VA_ARGS__)

extern module AP_MODULE_DECLARE_DATA dirlimit_module;

typedef struct {
    char *dirname;
    int counter;
} dirlimit_record;

typedef struct {
    int enabled;
    int limit;
    const char *base_path;
    apr_global_mutex_t *mutex;
    apr_shm_t *shm_data;
    char *strdata;
    dirlimit_record *records;
    size_t *records_num;
    uint64_t *n_total;
    uint64_t *n_rejected;
    uint64_t *n_lockerror;
} dirlimit_sconfig;

int binsearch(
    const void *key,
    const void *base,
    size_t nmemb,
    size_t size,
    size_t *pos,
    int (*compare)(const void *, const void *) )
{
    int lower, upper, middle;
    int ret;
    char *p;
    lower = 0;
    upper = nmemb-1;
    
    while( lower <= upper ) {
        middle = (lower + upper) / 2;
        p = (char*)base + size * middle;
        ret = compare( key, (void*)p );
        if( middle >= nmemb ) {
            DEBUGLOG("middle %d >= nmemb %d", middle, nmemb);
        }
        if( ret == 0 ) { /* key == base[middle] */
            *pos = middle;
            return 1;
        } else if( ret > 0 ) { /* key > base[middle] */
            lower = middle+1;
        } else { /* key < base[middle] */
            upper = middle-1;
        }
    }
    
    if( lower < 0 ) {
        *pos = 0;
    } else {
        *pos = lower;
    }
    return 0;
}

static int dirlimit_statushandler(request_rec *r)
{
    apr_status_t status = APR_SUCCESS;
    dirlimit_sconfig *conf =
        ap_get_module_config(r->server->module_config, &dirlimit_module);
    int i, slot;

    if (strcmp(r->handler, "dirlimit-status")) {
        return DECLINED;
    }

    status = apr_global_mutex_lock(conf->mutex);
    if( status != APR_SUCCESS ) {
        ERRORLOG("mod_dirlimit: global mutex lock faild(statushandler)");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    /* locked */
        DEBUGLOG("global mutex locked(statushandler)");
        r->no_cache = 1;
        r->content_type = "text/plain";
        ap_rprintf( r, "total_count: %ld\nrejected_count: %ld"
            "\nlockerror_count: %ld\nbase_path: %s\n",
            *(conf->n_total), *(conf->n_rejected), *(conf->n_lockerror), conf->base_path );
        ap_rprintf(r, "\nlimit: %d\n", conf->limit);
        ap_rprintf(r, "\nlimit records:\nrecord   slot  count dirname\n");
        for(i=0; i</* *(conf->records_num) */MAX_CLIENTS; i++ ) {
            slot = (int)(conf->records[i].dirname - conf->strdata) / MAX_DIRNAME;
            if( i == *(conf->records_num) ) {
                ap_rprintf(r,"------\n");
            }
            ap_rprintf( r, "%6d %6d %6d %s\n", i, slot, conf->records[i].counter, conf->records[i].dirname );
        }
    /************/
    
    status = apr_global_mutex_unlock(conf->mutex);

    DEBUGLOG("global mutex unlocked(statushandler)");
    return OK;
}

static int compare_record( const void *key, const void *r )
{
    const char *s;
    s = ((dirlimit_record*)r)->dirname;
    DEBUGLOG("compare: %s %s prt: %lX %lX", key, s, key, r);
    return strncmp(key,s,MAX_DIRNAME-1);
}

static inline void swap_slot( dirlimit_sconfig *conf )
{
    dirlimit_record *r = conf->records;
    size_t n = *(conf->records_num);
    char *t;
    
    /* partly sort */
    if( n > MAX_CLIENTS - 2 ) {
        return;
    }
    if( r[n].dirname > r[n+1].dirname ) {
        t = r[n].dirname;
        r[n].dirname = r[n+1].dirname;
        r[n+1].dirname = t;
    }
}

static int search_record( dirlimit_sconfig *conf, const char *key, size_t *pos )
{
    return binsearch( key, conf->records, *(conf->records_num),
        sizeof(dirlimit_record), pos, compare_record );
}

static void insert_record( dirlimit_sconfig *conf, const char *key, size_t pos )
{
    dirlimit_record *r = conf->records;
    size_t n = *(conf->records_num);
    char *dirname = r[n].dirname;
    
    memmove( &r[pos+1], &r[pos], sizeof(dirlimit_record)*(n-pos) );
    /*int i;
    for( i=n; i>=pos+1; i-- ) {
        r[i].dirname = r[i-1].dirname;
        r[i].counter = r[i-1].counter;
    }*/
    
    strncpy( dirname, key, MAX_DIRNAME-1 );
    dirname[MAX_DIRNAME-1] = '\0';
    r[pos].counter = 0;
    r[pos].dirname = dirname;
    (*(conf->records_num))++;
    DEBUGLOG("records_num=%d", *(conf->records_num) );
}

static void remove_record( dirlimit_sconfig *conf, size_t pos )
{
    dirlimit_record *r = conf->records;
    size_t n = *(conf->records_num);
    char *dirname = r[pos].dirname;
    
    memmove( &r[pos], &r[pos+1], sizeof(dirlimit_record)*(n-pos-1) );
    /*int i;
    for( i=pos; i<n-1; i++ ) {
        r[i].dirname = r[i+1].dirname;
        r[i].counter = r[i+1].counter;
    }*/
    
    r[n-1].dirname = dirname;
    //r[n-1].dirname[0] = '\0';
    //r[n-1].counter = 0;
    (*(conf->records_num))--;
    DEBUGLOG("records_num=%d", *(conf->records_num) );
    
    swap_slot(conf);
}

static int dirlimit_check_limit(request_rec *r)
{
    apr_status_t status = APR_SUCCESS;
    dirlimit_sconfig *conf =
        ap_get_module_config(r->server->module_config, &dirlimit_module);
    pid_t pid = getpid();
    int ret;
    size_t pos, n_bp;
    const char *dirname;
    
    /* is sub request ? */
    if( r->main || r->prev ) {
        DEBUGLOG("pass: it is sub request %s", r->filename);
        return OK;
    }
    
    DEBUGLOG("fixup: %s", r->filename );
    
    if( ! conf->enabled ) {
        DEBUGLOG("mod_dirlimit is disabled");
        return OK;
    }
    
    n_bp = strlen(conf->base_path);
    /* if r->filename is out of conf->base_path ? */
    if( strncmp( (char*)conf->base_path, r->filename, n_bp ) != 0 ) {
        DEBUGLOG("requested file is out of base_path");
        return OK;
    }
    
    dirname = &(r->filename[n_bp]);
    dirname = ap_getword( r->pool, &dirname, '/' );
    
    if( dirname[0] == '\0' ) {
        DEBUGLOG("not subdirectory");
        return OK;
    }
    
    DEBUGLOG("dirname: %s", dirname);

    status = apr_global_mutex_lock(conf->mutex);
    if(status == APR_SUCCESS){
        DEBUGLOG("global mutex locked");
    } else {
        ERRORLOG("mod_dirlimit: global mutex lock faild(pre-responce)");
        (*(conf->n_lockerror))++;
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    /* Locked */
    (*(conf->n_total))++;
    ret = search_record( conf, dirname, &pos );
    DEBUGLOG("pos:%d", pos);
    if( ! ret ) {
        if( *conf->records_num >= MAX_CLIENTS ) {
            ERRORLOG("mod_dirlimit: reached maxclients");
            status = apr_global_mutex_unlock(conf->mutex);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        insert_record( conf, dirname, pos );
        DEBUGLOG("inserted: pos=%d", pos);
    }
    
    if( conf->records[pos].counter >= conf->limit ) {
        ERRORLOG( "mod_dirlimit: reached per-dir connection limit(limit=%d file=%s base_path=%s dir=%s)",
            conf->limit, r->filename, conf->base_path, dirname );
        (*(conf->n_rejected))++;
        /* unlock */
        status = apr_global_mutex_unlock(conf->mutex);
        return HTTP_SERVICE_UNAVAILABLE;
    }
    conf->records[pos].counter++;
    DEBUGLOG("access_ok: counter=%d limit=%d", conf->records[pos].counter, conf->limit);
    /************/
    
    status = apr_global_mutex_unlock(conf->mutex);

    apr_table_set( r->notes, DIRNAME_INFO_KEY, dirname );
    
    /*uint64_t i,j;
    j = (uint64_t)time(NULL);
    for(i=1;i<1000000;i++) {
        j += (j%i);
    }
    DEBUGLOG("test:%ld", j);*/

    DEBUGLOG("global mutex unlocked");
    return OK;
}

static int dirlimit_response_end(request_rec *r)
{
    apr_status_t status = APR_SUCCESS;
    dirlimit_sconfig *conf =
        ap_get_module_config(r->server->module_config, &dirlimit_module);
    pid_t pid = getpid();
    size_t pos;
    int ret;
    const char* dirname;
    
    dirname = apr_table_get( r->notes, DIRNAME_INFO_KEY );
    if( ! dirname ) {
        DEBUGLOG("pass: dirname is not set");
        return OK;
    }

    status = apr_global_mutex_lock(conf->mutex);
    if(status == APR_SUCCESS){
        DEBUGLOG("global mutex locked");
    } else {
        ERRORLOG("mod_dirlimit: global mutex lock faild(responce_end)");
        return OK;
    }
    
    /* Locked */
    ret = search_record( conf, dirname, &pos );
    if( ! ret ) {
        ERRORLOG("mod_dirlimit: record not found(responce_end): dirname=%s", dirname);
    } else {
        conf->records[pos].counter--;
        if( conf->records[pos].counter > 0 ) {
            /* do nothing */
        } else {
            if( conf->records[pos].counter < 0 ) {
                ERRORLOG("mod_dirlimit: counter < 0(responce_end)");
            }
            remove_record( conf, pos );
            DEBUGLOG("removed record: pos=%d", pos);
        }
    }
    /************/
    
    status = apr_global_mutex_unlock(conf->mutex);

    DEBUGLOG("global mutex unlocked");
    return OK;
}

static void *create_server_config(apr_pool_t *p, server_rec *s){
    dirlimit_sconfig *newcfg = apr_pcalloc(p, sizeof(*newcfg));
    newcfg->enabled = 0;
    newcfg->shm_data = NULL;
    newcfg->mutex = NULL;
    return newcfg;
}

static const char *set_base_path(cmd_parms *cmd, void *dummy, const char *arg)
{
    dirlimit_sconfig *conf =
        ap_get_module_config(cmd->server->module_config, &dirlimit_module);
    int len;
    
    if( arg[0] != '/' ) {
        return "Invalid path (should be absolute path).";
    }
    conf->enabled = 1;
    len = strlen(arg);
    if( len > 1 && arg[len-1] != '/' ) {
        conf->base_path = apr_pstrcat(cmd->pool, arg, "/", NULL);
    } else {
        conf->base_path = apr_pstrdup(cmd->pool, arg);
    }
    return NULL;
}

static const char *set_limit(cmd_parms *cmd, void *dummy, const char *arg)
{
    dirlimit_sconfig *conf =
        ap_get_module_config(cmd->server->module_config, &dirlimit_module);
    int limit;
    limit = atoi(arg);
    if( limit < 0 ) {
        return "Invalid limit (should be positive num).";
    }
    conf->limit = limit;
    return NULL;
}

static int post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    dirlimit_sconfig *conf;
    void *user_data;
    apr_status_t status;
    size_t shm_size, retsize, i;

    apr_pool_userdata_get(&user_data, USER_DATA_KEY, s->process->pool);
    if(user_data == NULL) {
        apr_pool_userdata_set((const void *)1, USER_DATA_KEY, apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    do{
        conf = (dirlimit_sconfig*)(ap_get_module_config(s->module_config, &dirlimit_module));
        //Create global mutex
        status = apr_global_mutex_create(&(conf->mutex), MUTEX_PATH, APR_LOCK_DEFAULT, p);
        if(status != APR_SUCCESS) {
            ERRORLOG("mod_dirlimit: create gloval mutex faild");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
#ifdef AP_NEED_SET_MUTEX_PERMS
        status = unixd_set_global_mutex_perms(conf->mutex);
        if(status != APR_SUCCESS) {
           ERRORLOG("mod_dirlimit: Parent could not set permissions on globalmutex");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
#endif

        //Remove existing shared memory
        status = apr_shm_remove(SHM_PATH, p);
        if (status == APR_SUCCESS) {
            ERRORLOG("mod_dirlimit: removed existing shared memory file");
        }

        //Create shared memory
        shm_size = MAX_DIRNAME * MAX_CLIENTS + sizeof(dirlimit_record) * MAX_CLIENTS + sizeof(uint64_t)*3;
        status = apr_shm_create(&(conf->shm_data), shm_size, SHM_PATH, p);
        if(status != APR_SUCCESS) {
            ERRORLOG("mod_dirlimit: failed to create shared memory");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        
        retsize = apr_shm_size_get(conf->shm_data);
        if( retsize != shm_size ) {
            ERRORLOG("mod_dirlimit: ivalid shared memory size");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        conf->shm_data = apr_shm_baseaddr_get(conf->shm_data);
        conf->strdata = (char*)conf->shm_data;
        conf->records = (dirlimit_record*)&(conf->strdata[MAX_DIRNAME*MAX_CLIENTS]);
        conf->records_num = (size_t*)&conf->records[MAX_CLIENTS];
        conf->n_total = (uint64_t*)(conf->records_num + 1);
        conf->n_rejected = conf->n_total + 1;
        conf->n_lockerror = conf->n_total + 2;
        DEBUGLOG("conf->shm_data: %lX \nconf->strdata: %lX \nconf->records: %lX \nconf->records_num: %lX \n",
            conf->shm_data, conf->strdata, conf->records, conf->records_num );
        
        for( i=0; i<MAX_CLIENTS; i++ ) {
            conf->records[i].dirname = &(conf->strdata[i*MAX_DIRNAME]);
            conf->records[i].dirname[0] = '\0';
        }
        *(conf->records_num) = 0;
        
        *(conf->n_total) = 0;
        *(conf->n_rejected) = 0;
        *(conf->n_lockerror) = 0;
        DEBUGLOG("mod_dirlimit: init");
    } while( (s=s->next) != NULL );

    return OK;
}

static void init_child(apr_pool_t *p, server_rec *s)
{
    dirlimit_sconfig *conf;
    do{
        conf = (dirlimit_sconfig*)(ap_get_module_config(s->module_config, &dirlimit_module));
        if(!conf->shm_data){
            if(apr_global_mutex_child_init(&conf->mutex, MUTEX_PATH, p)) {
                DEBUGLOG("global mutex attached!");
            }
            if(apr_shm_attach(&(conf->shm_data), MUTEX_PATH, p) != APR_SUCCESS) {
                DEBUGLOG("shm attached!");
            }
            return;
        }
    } while( (s = s->next) != NULL );
}

static void dirlimit_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(init_child, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(dirlimit_check_limit, NULL, NULL, APR_HOOK_LAST);
    ap_hook_handler(dirlimit_statushandler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_log_transaction(dirlimit_response_end, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec dirlimit_cmds[] = {
    AP_INIT_TAKE1("DirLimitBasePath", set_base_path, NULL, OR_ALL,
        "DirLimitBasePath <path>"),
    AP_INIT_TAKE1("DirLimitNum", set_limit, NULL, OR_ALL,
        "DirLimitNum <num>"),
   {NULL}
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA dirlimit_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                    /* create per-dir    config structures */
    NULL,                    /* merge  per-dir    config structures */
    create_server_config,    /* create per-server config structures */
    NULL,                    /* merge  per-server config structures */
    dirlimit_cmds,           /* table of config file commands       */
    dirlimit_register_hooks  /* register hooks                      */
};

