#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_CC_URI_DENY_SHARE_MEMORY_NAME               ("HTTP_NGX_CC_URI_DENY_RSP_DENY_SHM")
#define NGX_HTTP_CC_URI_DENY_SHARE_MEMORY_MIN_SIZE           (1024 * 1024 * 100)

typedef struct time_node_s {
    struct time_node_s                  *prev;
    struct time_node_s                  *next;
    time_t                               time;
    int                                  count;
} time_node_t;

typedef struct time_rec_s {
    time_node_t                         *head;
    time_node_t                         *tail;
    ngx_int_t                            duration;
} time_rec_node_t;

typedef struct {
    ngx_rbtree_node_t                    node;
    time_rec_node_t                      time_rec_node;
} ngx_http_cc_deny_node_t;

typedef struct {
    ngx_str_t                            uri;
    ngx_array_t                          codes;
    ngx_int_t                            count;         /* match count */
    ngx_int_t                            duration;      /* duration    */
} ngx_http_cc_uri_deny_limit_cond_t;


typedef struct {
    ngx_rbtree_t      rbtree;
    ngx_rbtree_node_t sentinel;
} ngx_http_uri_cc_stats_shctx_t;

typedef struct {
    ngx_shm_zone_t                     * shm_zone_cc_rsp_deny;
    size_t                               shm_zone_size;
    ngx_http_uri_cc_stats_shctx_t      * shm_data;
} ngx_http_cc_uri_deny_main_conf_t;

typedef struct {
    ngx_array_t                          limit_array;
} ngx_http_cc_uri_deny_loc_conf_t;

static ngx_int_t ngx_http_cc_uri_deny_postconfig(ngx_conf_t* cf);
static void* ngx_http_cc_uri_deny_create_main_conf(ngx_conf_t* cf);
static char* ngx_http_cc_uri_deny_init_main_conf(ngx_conf_t* cf, void * conf);

static void* ngx_http_cc_uri_deny_create_conf(ngx_conf_t* cf);
static char * ngx_http_cc_uri_deny_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_cc_uri_deny_shm_zone_cc_rsp_deny_init(ngx_shm_zone_t *zone, void *data);

static char* ngx_http_cc_deny_uri_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);
static ngx_int_t ngx_http_cc_deny_handler_log_phase(ngx_http_request_t* r);
static ngx_int_t ngx_http_cc_deny_handler_access_phase(ngx_http_request_t* r);

static ngx_int_t ngx_http_cc_deny_init_module(ngx_cycle_t *cycle);

static ngx_http_module_t ngx_http_cc_uri_deny_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_cc_uri_deny_postconfig,        /* postconfiguration */

    ngx_http_cc_uri_deny_create_main_conf,  /* create main configuration */
    ngx_http_cc_uri_deny_init_main_conf,    /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_cc_uri_deny_create_conf,       /* create location configration */
    ngx_http_cc_uri_deny_merge_conf         /* merge location configration */
};
    
static ngx_command_t ngx_http_req_status_commands[] = {
    { ngx_string("CC_DENY_URI"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234 | NGX_CONF_TAKE5 | NGX_CONF_TAKE6,
      ngx_http_cc_deny_uri_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};
    
ngx_module_t ngx_http_cc_uri_deny_module = {
    NGX_MODULE_V1,
    &ngx_http_cc_uri_deny_module_ctx,       /* module context */
    ngx_http_req_status_commands,          /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    ngx_http_cc_deny_init_module,   /* init module */
    NULL,                           /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_cc_uri_deny_postconfig(ngx_conf_t* cf) {
    ngx_http_handler_pt* h;
    ngx_http_core_main_conf_t* cmcf;

    if (cf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, NULL, 0, "Configuration context is NULL in ngx_http_cc_deny_postconfig");
        return NGX_ERROR;
    }
    
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_cc_deny_handler_access_phase;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (cmcf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Failed to get core main configuration");
        return NGX_ERROR;
    }
    
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_cc_deny_handler_log_phase;

    return NGX_OK;
}


static void* ngx_http_cc_uri_deny_create_main_conf(ngx_conf_t* cf) {
    ngx_http_cc_uri_deny_main_conf_t* main_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cc_uri_deny_main_conf_t));

    if (main_conf == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "Failed to alloc main conf");
        return NULL;
    }
    
    main_conf->shm_zone_size = NGX_HTTP_CC_URI_DENY_SHARE_MEMORY_MIN_SIZE;
    main_conf->shm_zone_cc_rsp_deny = NULL;
    
    return main_conf;
}

static char* ngx_http_cc_uri_deny_init_main_conf(ngx_conf_t* cf, void * conf) {
    ngx_http_cc_uri_deny_main_conf_t* main_conf = (ngx_http_cc_uri_deny_main_conf_t* )conf;

    ngx_str_t rsp_name;
    ngx_str_set(&rsp_name, NGX_HTTP_CC_URI_DENY_SHARE_MEMORY_NAME);

    main_conf->shm_zone_size = NGX_HTTP_CC_URI_DENY_SHARE_MEMORY_MIN_SIZE;
    
    main_conf->shm_zone_cc_rsp_deny = ngx_shared_memory_add(cf, &rsp_name, 
                                                            main_conf->shm_zone_size, 
                                                            &ngx_http_cc_uri_deny_module);
    
    if (main_conf->shm_zone_cc_rsp_deny == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, NGX_ENOMOREFILES, 
                "Failed to add shared memory for response ");
        return NGX_CONF_ERROR;
    }
    
    main_conf->shm_zone_cc_rsp_deny->init = ngx_http_cc_uri_deny_shm_zone_cc_rsp_deny_init;
    main_conf->shm_zone_cc_rsp_deny->data = main_conf;
    
    return NGX_CONF_OK;
}


static ngx_int_t ngx_http_cc_deny_init_module(ngx_cycle_t *cycle) {
    return NGX_OK;
}

static void *
ngx_http_cc_uri_deny_create_conf(ngx_conf_t *cf)
{
    ngx_http_cc_uri_deny_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cc_uri_deny_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->limit_array.elts = NULL;
    return conf;
}


static char *
ngx_http_cc_uri_deny_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cc_uri_deny_loc_conf_t *prev = parent;
    ngx_http_cc_uri_deny_loc_conf_t *conf = child;

    if (conf->limit_array.elts == NULL) {
        conf->limit_array = prev->limit_array;
    }
    
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_cc_uri_deny_shm_zone_cc_rsp_deny_init(ngx_shm_zone_t *zone, void *data) {
    ngx_slab_pool_t *shpool;
    ngx_http_cc_uri_deny_main_conf_t *main_conf = (ngx_http_cc_uri_deny_main_conf_t *)zone->data; 

    shpool = (ngx_slab_pool_t *)zone->shm.addr;
    
    // Initialize new shared memory
    main_conf->shm_data = ngx_slab_alloc(shpool, sizeof(ngx_http_uri_cc_stats_shctx_t));
    
    if (main_conf->shm_data == NULL) {
        ngx_log_error(NGX_LOG_EMERG, zone->shm.log, 0, "Failed to allocate memory for main_conf");
        return NGX_ERROR;
    }
    ngx_memzero(main_conf->shm_data, sizeof(ngx_http_uri_cc_stats_shctx_t));

    ngx_rbtree_init(&main_conf->shm_data->rbtree, &main_conf->shm_data->sentinel, ngx_rbtree_insert_value);
    
    shpool->data = main_conf->shm_data;
    
    return NGX_OK;
}

ngx_int_t parse_request_frequency_value(char *str, ngx_int_t * count, ngx_int_t * duration) {
    if (str == NULL) {
        return NGX_ERROR;
    }

    // Find "times" keyword
    char *times_ptr = ngx_strstr(str, "times");
    if (times_ptr == NULL || times_ptr == str) {
        return NGX_ERROR;
    }

    // Parse the count before "times"
    ngx_str_t count_str;
    count_str.data = (u_char *)str;
    count_str.len = times_ptr - str;

    ngx_int_t ct = ngx_atoi(count_str.data, count_str.len);
    if (ct == NGX_ERROR || ct <= 0) {
        return NGX_ERROR;
    }
    *count = ct;

    // Move past "times" and look for '/'
    char *slash_ptr = strchr(times_ptr + 5, '/'); // +5 to skip "times"
    if (slash_ptr == NULL) {
        return NGX_ERROR;
    }

    // Parse the duration after '/'
    char *duration_str = slash_ptr + 1;
    size_t duration_len = strlen(duration_str);
    if (duration_len == 0) {
        return NGX_ERROR;
    }

    ngx_int_t multiplier = 1; // Default is seconds
    char unit = duration_str[duration_len - 1];

    if (unit == 's' || unit == 'm' || unit == 'h') {
        duration_len--; // Exclude the unit character
        switch (unit) {
            case 's':
                multiplier = 1;
                break;
            case 'm':
                multiplier = 60;
                break;
            case 'h':
                multiplier = 3600;
                break;
            default:
                return NGX_ERROR;
        }
    }

    if (duration_len == 0) {
        return NGX_ERROR;
    }

    ngx_str_t dur_str;
    dur_str.data = (u_char *)duration_str;
    dur_str.len = duration_len;

    ngx_int_t dr = ngx_atoi(dur_str.data, dur_str.len);
    if (dr == NGX_ERROR || dr <= 0) {
        return NGX_ERROR;
    }

    *duration = dr * multiplier;

    return NGX_OK;
}

static char* ngx_http_cc_deny_uri_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    // add limits here;
    
    //CC_DENY_URI bbbb.ts 500 100tims/500s
    
    if (cf->args->nelts != 4) 
        return NGX_CONF_ERROR;

    ngx_http_cc_uri_deny_limit_cond_t * limit_cond, *limits;
    
    ngx_http_cc_uri_deny_loc_conf_t * loc_conf = conf;
    ngx_str_t                       * value;
    value = cf->args->elts;

    // Parse codes
    char * str = ngx_pcalloc(cf->pool, value[2].len + 1);
    if (str == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(str, value[2].data, value[2].len);
    str[value[2].len] = '\0';

    char * save_ptr, delim[] = ",";
    char * token = strtok_r(str, delim, &save_ptr);

    ngx_array_t code_array;
    
    if (ngx_array_init(&code_array, cf->pool, 1,
                           sizeof(ngx_int_t))
            != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
            
    while (token != NULL) {
        int token_length = ngx_strlen(token);
        ngx_int_t code;
        code = ngx_atoi((u_char *)token, token_length);
        if (code <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid code value \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

        ngx_int_t * code_p = ngx_array_push(&code_array);
        if (code_p == NULL)
            return NGX_CONF_ERROR;
        *code_p = code;
        
        token = strtok_r(NULL, delim, &save_ptr);
    }

    // Parse rate and duration
    ngx_int_t count, duration;
    if (parse_request_frequency_value((char *)value[3].data, &count, &duration) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid rate value \"%V\"", &value[3]);
        return NGX_CONF_ERROR;
    }

    // Parse uri;
    ngx_str_t uri;
    uri.data = ngx_pstrdup(cf->pool, &value[1]);
    uri.len = value[1].len;
    
    limits = loc_conf->limit_array.elts;
    if (limits == NULL) {
        if (ngx_array_init(&loc_conf->limit_array, cf->pool, 1,
                           sizeof(ngx_http_cc_uri_deny_limit_cond_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }
    
    limit_cond = ngx_array_push(&loc_conf->limit_array);
    if (limit_cond == NULL) {
        return NGX_CONF_ERROR;
    }
    
    ngx_memcpy(&limit_cond->codes, &code_array, sizeof (ngx_array_t));
    limit_cond->uri.data  = uri.data;
    limit_cond->uri.len  = uri.len;
    limit_cond->count = count;
    limit_cond->duration = duration;

    return NGX_CONF_OK;
}


static ngx_int_t ngx_http_cc_deny_uri_check(ngx_http_request_t * r, ngx_str_t uri) {
    int i;
    ngx_str_t* p_uri = NULL;
    p_uri = &r->uri;

    // Remove HTTP version in uri path , /api/config HTTP/1.1
    
    ngx_str_t orig_uri;
    
    u_char * str_uri = ngx_pcalloc(r->pool, p_uri->len + 1);
    if (str_uri == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to alloc memory");
        return NGX_ERROR;
    }

    for (i = 0 ; i < (int)p_uri->len ; i ++) {
        if (p_uri->data[i] == ' ') {
            str_uri[i] = '\0';
            break;
        }
        str_uri[i] = p_uri->data[i];
    }
    if (str_uri[i] != '\0') 
        str_uri[i] = '\0';

    orig_uri.data = str_uri;
    orig_uri.len = i;
    
    if (orig_uri.len >= uri.len) {
        int j = orig_uri.len - 1;
        for (i = uri.len - 1; i >= 0 ; i --, j --) {
            if (uri.data[i] != orig_uri.data[j]) {
                break;
            }
        }
        if (i == -1) {
            return NGX_OK;
        }
    }
    return NGX_ERROR;
}

static ngx_int_t ngx_http_cc_deny_code_check(ngx_http_request_t *r, ngx_array_t * codes_array) {
    ngx_uint_t status_code;
    status_code = r->headers_out.status;

    if (codes_array == NULL)
        return NGX_ERROR;

    ngx_int_t * codes = codes_array->elts;
    
    for (ngx_uint_t i = 0 ; i < codes_array->nelts ; i ++ ) {
        if (codes[i] == (ngx_int_t)status_code)
            return NGX_OK;
    }
    
    return NGX_ERROR;
}

static void ngx_http_cc_uri_deny_clear_time_nodes (ngx_slab_pool_t  * shpool, time_rec_node_t * time_rec_node) {
     //Remove old time node
    time_t standard_time = time(NULL) - time_rec_node->duration;
    time_node_t * temp_node = time_rec_node->head;
    
    while (temp_node != NULL && temp_node->time < standard_time) {
        time_node_t * st_next = temp_node->next;
        ngx_slab_free_locked(shpool, temp_node);
        if (st_next != NULL) {
            st_next->prev = NULL;
            time_rec_node->head = st_next;
        } else {
            time_rec_node->head = NULL;
            time_rec_node->tail = NULL;
        }
        temp_node = st_next;
    }
}

static ngx_int_t ngx_http_cc_deny_handler_log_phase(ngx_http_request_t* r) {
    ngx_http_cc_uri_deny_main_conf_t * main_conf = NULL;
    main_conf = ngx_http_get_module_main_conf(r, ngx_http_cc_uri_deny_module);

    ngx_http_cc_uri_deny_loc_conf_t * loc_conf = NULL;
    loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_cc_uri_deny_module);

    if (main_conf->shm_zone_cc_rsp_deny == NULL)
        return NGX_DECLINED;
    
    ngx_slab_pool_t  *shpool = (ngx_slab_pool_t *) main_conf->shm_zone_cc_rsp_deny->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

    ngx_http_cc_uri_deny_limit_cond_t * limits = loc_conf->limit_array.elts;

    ngx_uint_t index;
    for (index = 0 ; index < loc_conf->limit_array.nelts; index ++) {
        if (ngx_http_cc_deny_uri_check(r, limits[index].uri) == NGX_OK
            && ngx_http_cc_deny_code_check(r, &limits[index].codes) == NGX_OK) {
            break;
        }
    }
    
    if (index == loc_conf->limit_array.nelts) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_OK;
    }

    ngx_http_cc_deny_node_t      *cc_node = NULL;
    ngx_rbtree_node_t            *node, *sentinel;
    time_rec_node_t              *time_rec_node = NULL;
    ngx_uint_t                    hash;
    
    hash = ngx_crc32_short(limits[index].uri.data, limits[index].uri.len);
    
    node = main_conf->shm_data->rbtree.root;
    sentinel = main_conf->shm_data->rbtree.sentinel;

    while (node != sentinel) {
        
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }
        
        /* hash == node->key */
        cc_node = (ngx_http_cc_deny_node_t *) node;
        break;
    }
    
    if (cc_node == NULL) {
        // Node not found, create new node
        
        cc_node = ngx_slab_alloc_locked(shpool, sizeof(ngx_http_cc_deny_node_t));
        if (cc_node == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_ERROR;
        }

        cc_node->node.key = hash;

        cc_node->time_rec_node.head = NULL;
        cc_node->time_rec_node.tail = NULL;
        cc_node->time_rec_node.duration = limits[index].duration;
        
        ngx_rbtree_insert(&main_conf->shm_data->rbtree, &cc_node->node);
    }

    time_rec_node = &cc_node->time_rec_node;
    
    //Remove old time node
    ngx_http_cc_uri_deny_clear_time_nodes(shpool, time_rec_node);
    
    time_node_t * time_node = ngx_slab_calloc_locked(shpool, sizeof (time_node_t));
    if (time_node == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to alloc time node");
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_DECLINED;
    }
    
    time_node->next = NULL;
    time_node->prev = NULL;
    time_node->time = time(NULL);
    time_node->count = 1;

    if (time_rec_node->head == NULL) {
        time_rec_node->head = time_node;
        time_rec_node->tail = time_node;
    } else if (time_rec_node->tail == NULL) {
        time_rec_node->tail = time_rec_node->head;
    } else {

        if (time_rec_node->tail->time == time_node->time) {
            time_rec_node->tail->count ++;
            ngx_slab_free_locked(shpool, time_node);
         }
        else {
            time_node->prev = time_rec_node->tail;
            time_rec_node->tail->next = time_node;
            time_rec_node->tail= time_node;
        }
    }
    
    ngx_shmtx_unlock(&shpool->mutex);
    
    return NGX_OK;
}

static ngx_int_t ngx_http_cc_deny_handler_access_phase(ngx_http_request_t* r) {
    ngx_http_cc_uri_deny_main_conf_t * main_conf = NULL;
    main_conf = ngx_http_get_module_main_conf(r, ngx_http_cc_uri_deny_module);

    ngx_http_cc_uri_deny_loc_conf_t * loc_conf = NULL;
    loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_cc_uri_deny_module);

    if (main_conf->shm_zone_cc_rsp_deny == NULL)
        return NGX_DECLINED;
    
    ngx_slab_pool_t  *shpool = (ngx_slab_pool_t *) main_conf->shm_zone_cc_rsp_deny->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    ngx_http_cc_uri_deny_limit_cond_t * limits = loc_conf->limit_array.elts;
    
    ngx_uint_t index;

    for (index = 0 ; index < loc_conf->limit_array.nelts ; index ++) {
        if (ngx_http_cc_deny_uri_check(r, limits[index].uri) == NGX_OK) {
            break;
        }
    }

    if (index == loc_conf->limit_array.nelts) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_DECLINED;
    }

    ngx_http_cc_deny_node_t      *cc_node = NULL;
    ngx_rbtree_node_t  *node, *sentinel;
    time_rec_node_t    *time_rec_node = NULL;
    ngx_uint_t          hash;
    
    hash = ngx_crc32_short(limits[index].uri.data, limits[index].uri.len);

    node = main_conf->shm_data->rbtree.root;
    sentinel = main_conf->shm_data->rbtree.sentinel;

    while (node != sentinel) {
        
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }
        
        /* hash == node->key */
        cc_node = (ngx_http_cc_deny_node_t *) node;
        break;
    }

    if (cc_node == NULL) {
       ngx_shmtx_unlock(&shpool->mutex);
       return NGX_DECLINED;
    }

    time_rec_node = &cc_node->time_rec_node;
    
    int match_count = 0 ;
    time_node_t * time_node_p = time_rec_node->tail;
        
    time_t now = time(NULL);
    while (time_node_p != NULL) {
        
        long diff_second = now - time_node_p->time;
        if (diff_second > time_rec_node->duration) {
            break;
        }
        
        match_count += time_node_p->count;

        if (match_count > limits[index].count || time_node_p == time_rec_node->head)
            break;
        
        time_node_p = time_node_p->prev;
    }

    //Remove old time node
    ngx_http_cc_uri_deny_clear_time_nodes(shpool, time_rec_node);

    if (match_count >= limits[index].count) {
        ngx_shmtx_unlock(&shpool->mutex);
        
        char str[2048] = {};
        ngx_int_t * codes = limits[index].codes.elts;
        for (ngx_uint_t i = 0 ; i < limits[index].codes.nelts ; i ++) {
            char temp[16];
            if (i == limits[index].codes.nelts - 1)
                snprintf(temp, 16, "%d", (int)codes[i]);
            else
                snprintf(temp, 16, "%d,", (int)codes[i]);
            strcat(str, temp);
        }
        
        if (limits[index].codes.nelts >= 2) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[CC_DENY_URI] [%V] exceeds the limit rates (%d)times per (%d)seconds for one of [%s] codes", 
                &limits[index].uri, limits[index].count, limits[index].duration, str);
        }
        else
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[CC_DENY_URI] [%V] exceeds the limit rates (%d)times per (%d)seconds for [%s]code", 
                &limits[index].uri, limits[index].count, limits[index].duration, str);
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }
    
    ngx_shmtx_unlock(&shpool->mutex);
    return NGX_DECLINED;
}




