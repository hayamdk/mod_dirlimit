#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_request.h"
#include "ap_config.h"
#include "apr_hooks.h"
#include "apr_strings.h"
#include "apr_global_mutex.h"
#include "apr_tables.h"
#include "unixd.h"

#ifdef AP_DECLARE_MODULE
#define APACHE24
#endif

#ifdef APACHE24
#define unixd_set_global_mutex_perms ap_unixd_set_global_mutex_perms
#endif

#define MAX_DIRNAME 64
#define MAX_CONFIGS 128

#define USER_DATA_KEY "mod_dirlimit_key"
#define DIRLIMIT_ORIGPATH "mod_dirlimit_origpath"
#define DIRLIMIT_ORIGTYPE "mod_dirlimit_origtype"
#define MUTEX_PATH NULL
#define SHM_PATH NULL

//#define DEBUGLOG(...) ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, NULL, __VA_ARGS__)
#define DEBUGLOG(...)
#define ERRORLOG(...) ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, __VA_ARGS__)

#define CONTEXT_DIRECTORY           1
#define CONTEXT_DIRECTORY_MATCH     2
#define CONTEXT_FILES               3
#define CONTEXT_FILES_MATCH         4
#define CONTEXT_LOCATION            5
#define CONTEXT_LOCATION_MATCH      6
#define CONTEXT_OTHERS              7

#define NO_SCRIPT_TYPE              ((const char*)1)
#define SCRIPT_TYPE                 ((const char*)2)

extern module AP_MODULE_DECLARE_DATA dirlimit_module;

typedef struct {
    int conf_id;
    char *dirname;
    int counter;
    int counter_script;
} dirlimit_record;

typedef struct {
    int allow_override;
    apr_global_mutex_t *mutex;
    apr_shm_t *shm_data;
    char *strdata;
    dirlimit_record *records;
    size_t records_size;
    size_t *records_num;
    uint64_t *n_total;
    uint64_t *n_rejected;
    uint64_t *n_lockerror;
} dirlimit_sconfig;

typedef struct dirlimit_dirconfig {
    int limit;
    int limit_script;
    int limit_sub;
    int limit_sub_script;
    apr_table_t *script_types;
    const char *path;
    int cmd_context;
    int sub;
    int pathdepth;
    int conf_id;
    struct dirlimit_dirconfig *parent;
} dirlimit_dirconfig;

static int post_config_flag = 0;
static int conf_counter = 0;
static dirlimit_dirconfig conf_list[MAX_CONFIGS];

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
            DEBUGLOG("middle %d >= nmemb %d", (int)middle, (int)nmemb);
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
    int i, slot, limit, limit_script;
    const char *path;

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
            "\nlockerror_count: %ld\n",
            *(conf->n_total), *(conf->n_rejected), *(conf->n_lockerror) );
        ap_rprintf(r, "\nlimit records:\n"
            "rec slt| cnt / lim|scnt /slim| cid|%15s dirname\n", "path");
        for(i=0; i</* *(conf->records_num) */conf->records_size; i++ ) {
            slot = (int)(conf->records[i].dirname - conf->strdata) / MAX_DIRNAME;
            if( i == *(conf->records_num) ) {
                ap_rprintf(r,"------\n");
            }
            if( i < *(conf->records_num) ) {
                if( conf->records[i].dirname[0] == '\0' ) {
                    limit = conf_list[ conf->records[i].conf_id ].limit;
                    limit_script = conf_list[ conf->records[i].conf_id ].limit_script;
                } else {
                    limit = conf_list[ conf->records[i].conf_id ].limit_sub;
                    limit_script = conf_list[ conf->records[i].conf_id ].limit_sub_script;
                }
                path = conf_list[ conf->records[i].conf_id ].path;
            } else {
                limit = 0;
                limit_script = 0;
                path = "null";
            }
            ap_rprintf( r, "%3d %3d|%4d /%4d|%4d /%4d|%4d|%15s %s\n",
                i, slot, conf->records[i].counter, limit,
                conf->records[i].counter_script, limit_script,
                conf->records[i].conf_id, path, conf->records[i].dirname );
        }
    /************/
    
    status = apr_global_mutex_unlock(conf->mutex);

    DEBUGLOG("global mutex unlocked(statushandler)");
    return OK;
}

static int compare_record( const void *keyv, const void *rv )
{
    dirlimit_record *key, *r;
    key = (dirlimit_record*)keyv;
    r = (dirlimit_record*)rv;
    const char *keydir;
    
    keydir = key->dirname;
    if( keydir == NULL ) {
        keydir = "";
    }
    
    DEBUGLOG("compare: id:%d dir:'%s' <> id:%d dir:'%s'",
            key->conf_id, keydir, r->conf_id, r->dirname);
    
    if( key->conf_id > r->conf_id ) {
        return 1;
    } else if( key->conf_id < r->conf_id ) {
        return -1;
    }
    return strncmp( keydir, r->dirname, MAX_DIRNAME-1 );
}

/* partly sort */
static inline void swap_slot( dirlimit_sconfig *conf )
{
    dirlimit_record *r = conf->records;
    size_t n = *(conf->records_num);
    char *t;

    if( n > conf->records_size - 2 ) {
        return;
    }
    if( r[n].dirname > r[n+1].dirname ) {
        t = r[n].dirname;
        r[n].dirname = r[n+1].dirname;
        r[n+1].dirname = t;
    }
}

static int search_record( dirlimit_sconfig *conf, const dirlimit_record *key, size_t *pos )
{
    return binsearch( key, conf->records, *(conf->records_num),
        sizeof(dirlimit_record), pos, compare_record );
}

static void insert_record( dirlimit_sconfig *conf, dirlimit_record *key, size_t pos )
{
    dirlimit_record *rs = conf->records;
    size_t n = *(conf->records_num);
    char *dirname;
    
    dirname = rs[n].dirname;
    memmove( &rs[pos+1], &rs[pos], sizeof(dirlimit_record)*(n-pos) );
    /*int i,ct;
    for( ct=0,i=n; i>=pos+1; i-- ) {
        rs[i].conf_id = rs[i-1].conf_id;
        rs[i].dirname = rs[i-1].dirname;
        rs[i].counter = rs[i-1].counter;
        rs[i].counter_script = rs[i-1].counter_script;
        ct++;
    }*/
    rs[pos].dirname = dirname;
    //DEBUGLOG("inserting: %d record moved", ct);
    
    DEBUGLOG("inserting: key->dirname=%s", key->dirname);
    if( key->dirname == NULL ) {
        rs[pos].dirname[0] = '\0';
    } else {
        strncpy( rs[pos].dirname, key->dirname, MAX_DIRNAME-1 );
        rs[pos].dirname[MAX_DIRNAME-1] = '\0';
    }
    rs[pos].conf_id = key->conf_id;
    rs[pos].counter = 0;
    rs[pos].counter_script = 0;
    (*(conf->records_num))++;
    DEBUGLOG("insert_record: rs[pos].dirname=%s", rs[pos].dirname);
    DEBUGLOG("insert_record: pos=%d records_num=%d", (int)pos, (int)*(conf->records_num) );
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
    DEBUGLOG("remove_record: pos=%d records_num=%d", (int)pos, (int)*(conf->records_num) );
    
    swap_slot(conf);
}

static inline char *get_dirname( apr_pool_t *pool, const char *path, int pathdepth )
{
    int i=0;
    const char *p = path;
    if( *p == '/' ) {
        p++;
    }
    for(i=0; i<pathdepth; p++ ) {
        if( *p == '/' ) {
            i++;
        } else if( *p == '\0' ) {
            return apr_pstrdup( pool, "!!nuknown dir!!" );
        }
    }
    return ap_getword( pool, &p, '/' );
}

static inline int get_pathdepth( const char *path )
{
    int i,l,c=0;
    const char *p = path;
    if( p[0] == '/' ) {
        p++;
    }
    l = strlen(p) - 1;
    if( l > 0 ) {
        c++;
    }
    for( i=0; i<l; i++ ) {
        if( p[i] == '/' ) {
            c++;
        }
    }
    return c;
}

static int check_limit( dirlimit_sconfig *sconf, dirlimit_record *r, int limit, const char* type )
{
    size_t ret, pos;

    ret = search_record( sconf, r, &pos );
    DEBUGLOG("pos:%d ret:%d", (int)pos, (int)ret);
    if( ! ret ) {
        if( *sconf->records_num >= sconf->records_size ) {
            ERRORLOG("mod_dirlimit: reached maxclients");
            (*(sconf->n_rejected))++;
            return -1;
        }
        DEBUGLOG("inserting: pos=%d", (int)pos);
        insert_record( sconf, r, pos );
        DEBUGLOG("inserted: pos=%d", (int)pos);
    }
    if( type == SCRIPT_TYPE ) {
        if( limit >= 0 && sconf->records[pos].counter_script >= limit ) {
            ERRORLOG("mod_dirlimit: reached per-dir script limit");
            (*(sconf->n_rejected))++;
            return -1;
        }
        (sconf->records[pos].counter_script)++;
        return sconf->records[pos].counter_script;
    } else {
        if( limit >= 0 && sconf->records[pos].counter >= limit ) {
            ERRORLOG("mod_dirlimit: reached per-dir connection limit");
            (*(sconf->n_rejected))++;
            return -1;
        }
        (sconf->records[pos].counter)++;
        return sconf->records[pos].counter;
    }
    return -1;
}

static int dirlimit_check_limit(request_rec *r)
{
    apr_status_t status = APR_SUCCESS;
    dirlimit_sconfig *sconf =
        ap_get_module_config(r->server->module_config, &dirlimit_module);
    dirlimit_dirconfig *dirconf, *dc;
    dirconf = ap_get_module_config(r->per_dir_config, &dirlimit_module);
    dirlimit_record record;
    int ret, limit;
    const char *type;
    
    /* is sub request ? */
    if( r->main || r->prev ) {
        DEBUGLOG("pass: it is sub request %s", r->filename);
        return OK;
    }
    
    DEBUGLOG("fixup: %s", r->filename );

    //return OK;

    /******* Lock *******/
    status = apr_global_mutex_lock(sconf->mutex);
    if(status == APR_SUCCESS){
        DEBUGLOG("global mutex locked(check_limit)");
    } else {
        ERRORLOG("mod_dirlimit: global mutex lock faild(check_limit)");
        (*(sconf->n_lockerror))++;
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    /******* Locked *******/
    (*(sconf->n_total))++;
    
    dc = dirconf;
    while(dc)
    {
        DEBUGLOG("%d:%s ->", dc->conf_id, dc->path);
        dc = dc->parent;
    }
    dc = dirconf;
    while( dc ) {
        type = apr_table_get( dc->script_types, r->handler );
        if( type != NULL ) { break; }
        dc = dc->parent;
    }
    apr_table_setn( r->notes, DIRLIMIT_ORIGTYPE, type );
    if( type == SCRIPT_TYPE ) {
        ERRORLOG( "!!!!script type!!" );
    } else if( type == NO_SCRIPT_TYPE ) {
        ERRORLOG( "!!!!no script type!!" );
    } else {
        ERRORLOG("!!!unknown!!");
    }
    
    dc = dirconf;
    while(dc) {
        record.conf_id = dc->conf_id;
        DEBUGLOG("aaaaaaa");
        /* per-dir */
        if( dc->limit >= 0  || dc->limit_script >= 0 ) {
            record.dirname = "";
            limit = dc->limit;
            if( type == SCRIPT_TYPE ) {
                limit = dc->limit_script;
            }
            ret = check_limit( sconf, &record, limit, type );
            if( ret < 0 ) {
                status = apr_global_mutex_unlock(sconf->mutex);
                return HTTP_SERVICE_UNAVAILABLE;
            }
            DEBUGLOG("access_ok(per-dir): counter=%d limit=%d", ret, dc->limit);
        }
        /* per-subdir */
        if( dc->limit_sub >= 0 || dc->limit_sub_script >= 0 ) {
            record.dirname = get_dirname( r->pool, r->filename, dc->pathdepth );
            DEBUGLOG("per-sub dirname %s",record.dirname);
            limit = dc->limit_sub;
            if( type == SCRIPT_TYPE ) {
                limit = dc->limit_sub_script;
            }
            ret = check_limit( sconf, &record, limit, type );
            if( ret < 0 ) {
                status = apr_global_mutex_unlock(sconf->mutex);
                return HTTP_SERVICE_UNAVAILABLE;
            }
            DEBUGLOG("access_ok(per-subdir): counter=%d limit=%d", ret, dc->limit);
        }
        
        DEBUGLOG("dirconf parent: %lX -> %lX", (long int)dc, (long int)dc->parent);
        dc = dc->parent;
    }
    
    /******* Unlock *******/
    status = apr_global_mutex_unlock(sconf->mutex);
    
    apr_table_set( r->notes, DIRLIMIT_ORIGPATH, r->filename );
    
    /*uint64_t i,j;
    j = (uint64_t)time(NULL);
    for(i=1;i<1000000;i++) {
        j += (j%i);
    }
    DEBUGLOG("test:%ld", j);*/

    DEBUGLOG("global mutex unlocked(check_limit)");
    return OK;
}

static int dirlimit_response_end(request_rec *r)
{
    apr_status_t status = APR_SUCCESS;
    dirlimit_sconfig *sconf =
        ap_get_module_config(r->server->module_config, &dirlimit_module);
    dirlimit_dirconfig *dirconf, *dc;
    dirconf = ap_get_module_config(r->per_dir_config, &dirlimit_module);
    size_t pos;
    int ret;
    const char *filename, *type;
    dirlimit_record record;
    
    filename = apr_table_get( r->notes, DIRLIMIT_ORIGPATH );
    if( ! filename ) {
        DEBUGLOG("pass: filename is not set");
        return OK;
    }
    type = apr_table_get( r->notes, DIRLIMIT_ORIGTYPE );

    status = apr_global_mutex_lock(sconf->mutex);
    if(status == APR_SUCCESS){
        DEBUGLOG("global mutex locked(responce_end)");
    } else {
        ERRORLOG("mod_dirlimit: global mutex lock faild(responce_end)");
        (*(sconf->n_lockerror))++;
        return OK;
    }
    
    /******* Locked *******/
    dc = dirconf;
    while(dc) {
        record.conf_id = dc->conf_id;
        /* per-dir */
        if( dc->limit >= 0  || dc->limit_script >= 0 ) {
            record.dirname = "";
            ret = search_record( sconf, &record, &pos );
            if( !ret ) {
                ERRORLOG("mod_dirlimit: per-dir record not found(responce_end)");
            } else {
                if( type == SCRIPT_TYPE ) {
                    (sconf->records[pos].counter_script)--;
                } else {
                    (sconf->records[pos].counter)--;
                }
                if( sconf->records[pos].counter == 0 && sconf->records[pos].counter_script == 0 ) {
                    remove_record( sconf, pos );
                } else if( sconf->records[pos].counter < 0 || sconf->records[pos].counter_script < 0 ) {
                    ERRORLOG("mod_dirlimit: per-dir counter < 0 (responce_end)");
                }
            }
        }
        /* per-subdir */
        if( dc->limit_sub >= 0 || dc->limit_sub_script >= 0 ) {
            record.dirname = get_dirname( r->pool, filename, dc->pathdepth );
            DEBUGLOG("per-sub dirname %s",record.dirname);
            ret = search_record( sconf, &record, &pos );
            if( !ret ) {
                ERRORLOG("mod_dirlimit: per-subdir record not found(responce_end)");
            } else {
                if( type == SCRIPT_TYPE ) {
                    (sconf->records[pos].counter_script)--;
                } else {
                    (sconf->records[pos].counter)--;
                }
                if( sconf->records[pos].counter == 0 && sconf->records[pos].counter_script == 0 ) {
                    remove_record( sconf, pos );
                } else if( sconf->records[pos].counter < 0 || sconf->records[pos].counter_script < 0 ) {
                    ERRORLOG("mod_dirlimit: per-dir counter < 0 (responce_end)");
                }
            }
        }
        
        dc = dc->parent;
    }
    /************/
    
    status = apr_global_mutex_unlock(sconf->mutex);

    DEBUGLOG("global mutex unlocked(responce_end)");
    return OK;
}

static void *create_server_config(apr_pool_t *p, server_rec *s)
{
    dirlimit_sconfig *newcfg = apr_pcalloc(p, sizeof(*newcfg));
    newcfg->allow_override = 0;
    newcfg->shm_data = NULL;
    newcfg->mutex = NULL;
    newcfg->records_size = 128;
    
    DEBUGLOG("create_server_config: %ld at pool %ld\n", (long int)newcfg, (long int)p);
    return newcfg;
}

static void *create_perdir_config(apr_pool_t *p, char *path)
{
    DEBUGLOG("bbbb\n");
    dirlimit_dirconfig *newcfg = apr_pcalloc(p, sizeof(*newcfg));
    newcfg->path = path;
    newcfg->parent = NULL;
    newcfg->limit = -1;
    newcfg->limit_sub = -1;
    newcfg->limit_script = -1;
    newcfg->limit_sub_script = -1;
    newcfg->script_types = apr_table_make(p,8);
    
    if( post_config_flag || conf_counter >= MAX_CONFIGS ) {
        newcfg->conf_id = -1;
    } else {
        newcfg->conf_id = conf_counter++;
    }
    DEBUGLOG("create_perdir_config: %s %ld at pool %ld\n", path, (long int)newcfg, (long int)p);
    return newcfg;
}

static void *merge_perdir_config(apr_pool_t *p, void *basev, void *overridev)
{
    dirlimit_dirconfig *base, *override, *new, *root_copy, *root, *child;
    base = (dirlimit_dirconfig*)basev;
    override = (dirlimit_dirconfig*)overridev;
    
    DEBUGLOG( "%s(%d,%d) id:%d -> %s(%d,%d) id:%d\n", base->path, base->limit, base->limit_sub, base->conf_id,
    override->path, override->limit, override->limit_sub, override->conf_id);
    
    new = (dirlimit_dirconfig*)apr_pcalloc(p, sizeof(dirlimit_dirconfig));
    *new = *override;
    
    if( override->parent == NULL ) {
        new->parent = base;
    } else {
        root = override;
        while(root->parent) {
            child = root;
            root = root->parent;
        }
        root_copy = (dirlimit_dirconfig*)apr_pcalloc(p, sizeof(dirlimit_dirconfig));
        *root_copy = *root;
        root_copy->parent = base;
        child->parent = root_copy;
    }
    
    return new;
}

static int get_cmd_context(cmd_parms *cmd)
{
    if( cmd->directive->parent ) {
        const char *directive = cmd->directive->parent->directive;
        const char *args = cmd->directive->parent->args;
        if( strcasecmp(directive,"<Directory") == 0 ) {
            if( args[0] == '~' ) {
                return CONTEXT_DIRECTORY_MATCH;
            } else {
                return CONTEXT_DIRECTORY;
            }
        } else if( strcasecmp(directive,"<DirectoryMatch") == 0 ) {
            return CONTEXT_DIRECTORY_MATCH;
        } else if( strcasecmp(directive,"<Files") == 0 ) {
            if( args[0] == '~' ) {
                return CONTEXT_FILES_MATCH;
            } else {
                return CONTEXT_FILES;
            }
        } else if( strcasecmp(directive,"<FilesMatch") == 0 ) {
            return CONTEXT_FILES_MATCH;
        } else if( strcasecmp(directive,"<Location") == 0 ) {
            if( args[0] == '~' ) {
                return CONTEXT_LOCATION_MATCH;
            } else {
                return CONTEXT_LOCATION;
            }
        } else if( strcasecmp(directive,"<LocationMatch") == 0 ) {
            return CONTEXT_LOCATION_MATCH;
        }
    }
    return CONTEXT_OTHERS;
}

const char *str_context(int c)
{
    if( c == CONTEXT_DIRECTORY ) {
        return "CONTEXT_DIRECTORY";
    } else if( c == CONTEXT_DIRECTORY_MATCH ) {
        return "CONTEXT_DIRECTORY_MATCH";
    } else if( c == CONTEXT_FILES ) {
        return "CONTEXT_FILES";
    } else if( c == CONTEXT_FILES_MATCH ) {
        return "CONTEXT_FILES_MATCH";
    } else if( c == CONTEXT_LOCATION ) {
        return "CONTEXT_LOCATION";
    } else if( c == CONTEXT_LOCATION_MATCH ) {
        return "CONTEXT_LOCATION_MATCH";
    } else {
        return "CONTEXT_OTHERS";
    }
}

static const char *set_limit(cmd_parms *cmd, void *dummy, const char *arg)
{
    dirlimit_dirconfig *dirconf = (dirlimit_dirconfig*)dummy;
    int limit;
    limit = atoi(arg);
    if( limit < 0 ) {
        return "Invalid limit (should be positive num).";
    }
    if( ! post_config_flag && dirconf->conf_id < 0 ) {
        return "Too many configs.";
    }
    dirconf->limit = limit;
    conf_list[ dirconf->conf_id ] = *dirconf;
    return NULL;
}

static const char *set_limit_sub(cmd_parms *cmd, void *dummy, const char *arg)
{
    dirlimit_dirconfig *dirconf = (dirlimit_dirconfig*)dummy;
    int limit;
    limit = atoi(arg);
    if( limit < 0 ) {
        return "Invalid limit (should be positive num).";
    }
    if( ! post_config_flag && dirconf->conf_id < 0 ) {
        return "Too many configs.";
    }
    dirconf->cmd_context = get_cmd_context(cmd);
    if( dirconf->cmd_context == CONTEXT_DIRECTORY || dirconf->cmd_context == CONTEXT_LOCATION ) {
        dirconf->pathdepth = get_pathdepth(dirconf->path);
    } else {
        return "Per-subdirectory limit is allowd in only <Directory> or <Location>.";
    }
    dirconf->limit_sub = limit;
    conf_list[ dirconf->conf_id ] = *dirconf;
    return NULL;
}

static const char *set_limit_script(cmd_parms *cmd, void *dummy, const char *arg)
{
    dirlimit_dirconfig *dirconf = (dirlimit_dirconfig*)dummy;
    int limit;
    limit = atoi(arg);
    if( limit < 0 ) {
        return "Invalid limit (should be positive num).";
    }
    if( ! post_config_flag && dirconf->conf_id < 0 ) {
        return "Too many configs.";
    }
    dirconf->limit_script = limit;
    conf_list[ dirconf->conf_id ] = *dirconf;
    return NULL;
}

static const char *set_limit_script_sub(cmd_parms *cmd, void *dummy, const char *arg)
{
    dirlimit_dirconfig *dirconf = (dirlimit_dirconfig*)dummy;
    int limit;
    limit = atoi(arg);
    if( limit < 0 ) {
        return "Invalid limit (should be positive num).";
    }
    if( ! post_config_flag && dirconf->conf_id < 0 ) {
        return "Too many configs.";
    }
    dirconf->cmd_context = get_cmd_context(cmd);
    if( dirconf->cmd_context == CONTEXT_DIRECTORY || dirconf->cmd_context == CONTEXT_LOCATION ) {
        dirconf->pathdepth = get_pathdepth(dirconf->path);
    } else {
        return "Per-subdirectory limit is allowed in only <Directory> or <Location>.";
    }
    dirconf->limit_sub_script = limit;
    conf_list[ dirconf->conf_id ] = *dirconf;
    return NULL;
}

static const char *set_script_type(cmd_parms *cmd, void *dummy, const char *arg)
{
    dirlimit_dirconfig *dirconf = (dirlimit_dirconfig*)dummy;
    apr_table_setn( dirconf->script_types, arg, SCRIPT_TYPE );
    return NULL;
}

static const char *set_noscript_type(cmd_parms *cmd, void *dummy, const char *arg)
{
    dirlimit_dirconfig *dirconf = (dirlimit_dirconfig*)dummy;
    apr_table_setn( dirconf->script_types, arg, NO_SCRIPT_TYPE );
    return NULL;
}

static const char *set_table_size(cmd_parms *cmd, void *dummy, const char *arg)
{
    dirlimit_sconfig *conf =
        ap_get_module_config(cmd->server->module_config, &dirlimit_module);
    int size = atoi(arg);
    if( size < 16 ) {
        return "Invalid table size (should be >= 16).";
    }
    conf->records_size = size;
    DEBUGLOG("tablesize set %d", size);
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
        shm_size = MAX_DIRNAME * conf->records_size +
                sizeof(dirlimit_record) * conf->records_size + sizeof(uint64_t)*3;
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
        conf->records = (dirlimit_record*)&(conf->strdata[MAX_DIRNAME*conf->records_size]);
        conf->records_num = (size_t*)&conf->records[conf->records_size];
        conf->n_total = (uint64_t*)(conf->records_num + 1);
        conf->n_rejected = conf->n_total + 1;
        conf->n_lockerror = conf->n_total + 2;
        DEBUGLOG("conf->shm_data: %lX \nconf->strdata: %lX \nconf->records: %lX \nconf->records_num: %lX \n",
            (long int)conf->shm_data, (long int)conf->strdata, (long int)conf->records, (long int)conf->records_num );
        
        for( i=0; i<conf->records_size; i++ ) {
            conf->records[i].dirname = &(conf->strdata[i*MAX_DIRNAME]);
            conf->records[i].dirname[0] = '\0';
        }
        *(conf->records_num) = 0;
        
        *(conf->n_total) = 0;
        *(conf->n_rejected) = 0;
        *(conf->n_lockerror) = 0;
        DEBUGLOG("mod_dirlimit: init");
    } while( (s=s->next) != NULL );
    
    post_config_flag = 1;

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
    AP_INIT_TAKE1("DirLimit", set_limit, NULL, ACCESS_CONF,
        "DirLimit <num>"),
    AP_INIT_TAKE1("DirLimitScript", set_limit_script, NULL, ACCESS_CONF,
        "DirLimitScript <num>"),
    AP_INIT_TAKE1("DirLimitPerSub", set_limit_sub, NULL, ACCESS_CONF,
        "DirLimitPerSub <num>"),
    AP_INIT_TAKE1("DirLimitScriptPerSub", set_limit_script_sub, NULL, ACCESS_CONF,
        "DirLimitScriptPerSub <num>"),
    AP_INIT_ITERATE("DirLimitSetScriptType", set_script_type, NULL, RSRC_CONF | OR_LIMIT,
        "DirLimitSetScriptType mime-type1 [mime-type2] ..."),
    AP_INIT_ITERATE("DirLimitSetNoScriptType", set_noscript_type, NULL, RSRC_CONF | OR_LIMIT,
        "DirLimitSetNoScriptType mime-type1 [mime-type2] ..."),
    AP_INIT_TAKE1("DirLimitTableSize", set_table_size, NULL, RSRC_CONF,
        "DirLimitTableSize <size>"),
   {NULL}
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA dirlimit_module = {
    STANDARD20_MODULE_STUFF, 
    create_perdir_config,    /* create per-dir    config structures */
    merge_perdir_config,     /* merge  per-dir    config structures */
    create_server_config,    /* create per-server config structures */
    NULL,                    /* merge  per-server config structures */
    dirlimit_cmds,           /* table of config file commands       */
    dirlimit_register_hooks  /* register hooks                      */
};

