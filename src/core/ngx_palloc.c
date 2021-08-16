
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


static ngx_inline void *ngx_palloc_small(ngx_pool_t *pool, size_t size,
    ngx_uint_t align);
static void *ngx_palloc_block(ngx_pool_t *pool, size_t size);
static void *ngx_palloc_large(ngx_pool_t *pool, size_t size);


ngx_pool_t *
/* 创建内存池 */
ngx_create_pool(size_t size, ngx_log_t *log)
{
    ngx_pool_t  *p;     // 执行内存池的头部

    /* 分配大小为size的内存 */
    p = ngx_memalign(NGX_POOL_ALIGNMENT, size, log);
    if (p == NULL) {
        return NULL;
    }

    /* 初始化 ngx_pool_t */
    p->d.last = (u_char *) p + sizeof(ngx_pool_t);
    p->d.end = (u_char *) p + size;
    p->d.next = NULL;
    p->d.failed = 0;

    /* 可供分配的空间大小 */
    size = size - sizeof(ngx_pool_t);
    /* 不能超过最大的限定值 */
    p->max = (size < NGX_MAX_ALLOC_FROM_POOL) ? size : NGX_MAX_ALLOC_FROM_POOL;

    p->current = p;     // 指向当前内存池
    p->chain = NULL;
    p->large = NULL;
    p->cleanup = NULL;
    p->log = log;

    return p;
}


/* 销毁内存池 */
void
ngx_destroy_pool(ngx_pool_t *pool)
{
    ngx_pool_t          *p, *n;
    ngx_pool_large_t    *l;
    ngx_pool_cleanup_t  *c;

    /* 若注册了cleanup,则遍历该链表结构,依次调用handler函数清理数据 */
    for (c = pool->cleanup; c; c = c->next) {
        if (c->handler) {
            ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                           "run cleanup: %p", c);
            c->handler(c->data);
        }
    }

/* 
 * 在 debug 模式下执行 if 和 endif 之间的代码
 * 主要用于 log 记录,跟踪函数销毁时日志信息
 */
#if (NGX_DEBUG)

    /*
     * we could allocate the pool->log from this pool
     * so we cannot use this log while free()ing the pool
     */

    for (l = pool->large; l; l = l->next) {
        ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0, "free: %p", l->alloc);
    }

    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                       "free: %p, unused: %uz", p, p->d.end - p->d.last);

        if (n == NULL) {
            break;
        }
    }

#endif

    /* 遍历 large 链表,释放大内存块 */
    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            ngx_free(l->alloc);
        }
    }

    /* 遍历所有分配的内存池,释放内存池结构 */
    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        ngx_free(p);

        if (n == NULL) {
            break;
        }
    }
}


/* 重置内存池 */
void
ngx_reset_pool(ngx_pool_t *pool)
{
    ngx_pool_t        *p;
    ngx_pool_large_t  *l;

    /* 遍历大块内存链表,释放大块内存 */
    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            ngx_free(l->alloc);
        }
    }

    /* 将 last 指针重新指向 ngx_pool_t 结构之后数据区开始的位置
     * 使内存池恢复到创建时的位置
     */
    for (p = pool; p; p = p->d.next) {
        p->d.last = (u_char *) p + sizeof(ngx_pool_t);
        p->d.failed = 0;
    }

    pool->current = pool;
    pool->chain = NULL;
    pool->large = NULL;
}


/* 从内存池中分配size大小的内存,取得的内存是对齐的 */
void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
#if !(NGX_DEBUG_PALLOC)
    /* 若请求的内存大小 size 小于内存池最大值 max,
     * 则进行小内存分配*/
    if (size <= pool->max) {
        return ngx_palloc_small(pool, size, 1);
    }
#endif

    /* 若所请求的内存大小 size 大于 max 则调用大块内存分配函数 */
    return ngx_palloc_large(pool, size);
}


/* 非对齐分配内存 */
void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
#if !(NGX_DEBUG_PALLOC)
    if (size <= pool->max) {
        return ngx_palloc_small(pool, size, 0);
    }
#endif

    return ngx_palloc_large(pool, size);
}


static ngx_inline void *
ngx_palloc_small(ngx_pool_t *pool, size_t size, ngx_uint_t align)
{
    u_char      *m;
    ngx_pool_t  *p;

    p = pool->current;

    do {
        m = p->d.last;

        if (align) {
            // 执行对齐操做
            m = ngx_align_ptr(m, NGX_ALIGNMENT);
        }

        /* 检查现有内存池是否有足够的内存空间,
         * 若有足够的空间,则移动last指针位置
         * 并返回分配内存地址的起始地址*/
        if ((size_t) (p->d.end - m) >= size) {
            p->d.last = m + size;

            return m;
        }

        // 若不满足则查找下一个内存池
        p = p->d.next;

    } while (p);

    // 如果遍历完整个内存池链表均未找到合适大小的内存块供分配，则执行 ngx_palloc_block
    // ngx_palloc_block 函数为该内存池再分配一个block，该 block 的大小为链表中前面每一个block
    // 大小的值。一个内存池是由多个block链接起来的。分配成功后，将该block加入到poll链的最后，
    // 同时，为所要分配的size大小的内存进行分配，并返回分配内存的起始位置。
    return ngx_palloc_block(pool, size);
}


static void *
ngx_palloc_block(ngx_pool_t *pool, size_t size)
{
    u_char      *m;
    size_t       psize;
    ngx_pool_t  *p, *new;

    // 计算pool的大小，即需要分配新的block的大小
    psize = (size_t) (pool->d.end - (u_char *) pool);

    // 执行按NGX_POOL_ALIGNMENT对齐方式的内存分配，假设能够分配成功，则继续执行后续代码片段
    m = ngx_memalign(NGX_POOL_ALIGNMENT, psize, pool->log);
    if (m == NULL) {
        return NULL;
    }

    // 执行 block 相关的初始化
    new = (ngx_pool_t *) m;

    new->d.end = m + psize;
    new->d.next = NULL;
    new->d.failed = 0;

    // 让m指向该内存 ngx_pool_data_t 结果体之后数据区的起始位置
    m += sizeof(ngx_pool_data_t);
    m = ngx_align_ptr(m, NGX_ALIGNMENT);
    // 在数据区分配size大小的内存并设置last指针
    new->d.last = m + size;

    for (p = pool->current; p->d.next; p = p->d.next) {
        if (p->d.failed++ > 4) {
            // 失败4次以上移动current指针
            pool->current = p->d.next;
        }
    }

    // 将分配的 block 链入内存
    p->d.next = new;

    return m;
}


// 这是一个 static的函数，说明外部函数不会随便调用，而是提供给内部函数调用的，
// 即 nginx 在进行内存分配需求时，不会去判断是大块内存还是小块内存，
// 而是交由内存分配函数去判断，对于用户需求来说是完全透明的。
static void *
ngx_palloc_large(ngx_pool_t *pool, size_t size)
{
    void              *p;
    ngx_uint_t         n;
    ngx_pool_large_t  *large;

    // 内存分配
    p = ngx_alloc(size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    n = 0;
    
    // 以下几行，将分配的内存链入pool的large链中，
    // 这里指原始pool在之前已经分配过large内存的情况
    for (large = pool->large; large; large = large->next) {
        if (large->alloc == NULL) {
            large->alloc = p;
            return p;
        }

        if (n++ > 3) {
            break;
        }
    }

    // 如果该 pool 之前并未分配 large 内存，则就没有 ngx_pool_large_t 来管理大块内存
    // 执行 ngx_pool_large_t 结构体的分配，用于来管理 large 内存块
    large = ngx_palloc_small(pool, sizeof(ngx_pool_large_t), 1);
    if (large == NULL) {
        ngx_free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}


// 分配 size 大小的内存并按 alignment 对齐，然后挂到 arge 字段下，
// 当做大块内存处理
void *
ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment)
{
    void              *p;
    ngx_pool_large_t  *large;

    p = ngx_memalign(alignment, size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    large = ngx_palloc_small(pool, sizeof(ngx_pool_large_t), 1);
    if (large == NULL) {
        ngx_free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}

/* 释放大内存块
 * 该函数只释放 large 链表中注册的内存，
 * 普通内存在 ngx_destroy_pool 中统一释放
 */
ngx_int_t
ngx_pfree(ngx_pool_t *pool, void *p)
{
    ngx_pool_large_t  *l;

    for (l = pool->large; l; l = l->next) {
        if (p == l->alloc) {
            ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                           "free: %p", l->alloc);
            ngx_free(l->alloc);
            l->alloc = NULL;

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


// 直接调用 palloc 函数，在进行一次 0 初始化
void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    void *p;

    p = ngx_palloc(pool, size);
    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}

/* 注册 cleanup；
 * size 是 data 字段所指向的资源的大小
 */
ngx_pool_cleanup_t *
ngx_pool_cleanup_add(ngx_pool_t *p, size_t size)
{
    ngx_pool_cleanup_t  *c;

    c = ngx_palloc(p, sizeof(ngx_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    if (size) {
        c->data = ngx_palloc(p, size);
        if (c->data == NULL) {
            return NULL;
        }

    } else {
        c->data = NULL;
    }

    c->handler = NULL;
    c->next = p->cleanup;

    p->cleanup = c;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, p->log, 0, "add cleanup: %p", c);

    return c;
}


/* 对内存池进行文件清理操作，即执行 handler，
 * 此时 handler == ngx_pool_cleanup_file
 */
void
ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd)
{
    ngx_pool_cleanup_t       *c;
    ngx_pool_cleanup_file_t  *cf;

    // 遍历cleanup结构链表，并执行handler
    for (c = p->cleanup; c; c = c->next) {
        if (c->handler == ngx_pool_cleanup_file) {

            cf = c->data;

            if (cf->fd == fd) {
                c->handler(cf);
                c->handler = NULL;
                return;
            }
        }
    }
}


/* 关闭data指定的文件句柄 */
void
ngx_pool_cleanup_file(void *data)
{
    // 指向 data 所指向的文件句柄
    ngx_pool_cleanup_file_t  *c = data;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d",
                   c->fd);

    // 关闭指定文件
    if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", c->name);
    }
}


/* 删除data指定的文件 */
void
ngx_pool_delete_file(void *data)
{
    ngx_pool_cleanup_file_t  *c = data;

    ngx_err_t  err;

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d %s",
                   c->fd, c->name);

    // 删除 data 所指定的文件
    if (ngx_delete_file(c->name) == NGX_FILE_ERROR) {
        err = ngx_errno;

        if (err != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_CRIT, c->log, err,
                          ngx_delete_file_n " \"%s\" failed", c->name);
        }
    }

    // 关闭文件句柄
    if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", c->name);
    }
}


#if 0

static void *
ngx_get_cached_block(size_t size)
{
    void                     *p;
    ngx_cached_block_slot_t  *slot;

    if (ngx_cycle->cache == NULL) {
        return NULL;
    }

    slot = &ngx_cycle->cache[(size + ngx_pagesize - 1) / ngx_pagesize];

    slot->tries++;

    if (slot->number) {
        p = slot->block;
        slot->block = slot->block->next;
        slot->number--;
        return p;
    }

    return NULL;
}

#endif
