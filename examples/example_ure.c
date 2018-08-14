#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>

#include "../log.h"
#include "./eutils.h"
#include "internal.h"
#include "evhtp/evhtp.h"
#include "evhtp/logutils.h"

#include <oniguruma.h>

regex_t * match = NULL;

struct data {
    OnigRegion * region;
    UChar      * str;
};


static int
name_callback(const UChar * name, const UChar * name_end,
              int ngroup_num, int * group_nums,
              regex_t * reg, void * arg)
{
    int           i, gn, ref;
    char        * s;
    struct data * data   = arg;
    OnigRegion  * region = (OnigRegion * )data->region;
    UChar       * str    = data->str;

    int           num;

    num = onig_name_to_backref_number(match, name, name_end, region);
    printf("%.*s = %.*s\n", name_end - name, name, region->end[num] - region->beg[num],
           (str + region->beg[num]));
    return 0;
}

static void
process_request_(evhtp_request_t * req, void * arg)
{
    (void)arg;
    OnigRegion * region = onig_region_new();
    char       * start;
    char       * range;
    char       * end;
    char       * str;

    str   = req->uri->path->full;
    end   = str + strlen(str);
    start = str;
    range = end;

    int r = onig_search(match, str, end, start, range, region, ONIG_OPTION_NONE);

    printf("%d\n", r);

    printf("hi %d\n", region->num_regs);

    if (r >= 0) {
        fprintf(stderr, "match at %d\n\n", r);
        struct data d;
        d.region = region;
        d.str    = str;
        onig_foreach_name(match, name_callback, &d);
    }



    htp_log_request(arg, stderr, req);
    evhtp_send_reply(req, EVHTP_RES_OK);

    onig_region_free(region, 1);
}

int
main(int argc, char ** argv)
{
    (void)argc;
    (void)argv;
    struct event_base * evbase;
    struct evhtp      * htp;
    void              * log;

    match = calloc(sizeof(*match), 1);
    evhtp_alloc_assert(match);

    char        * pattern = "/user/(?<foo>\\w+)/(?<bar>\\w+)$";

    OnigErrorInfo errinfo;
    onig_new_without_alloc(match,
                           (const OnigUChar *)pattern,
                           (const OnigUChar *)pattern + strlen(pattern),
                           ONIG_OPTION_DEFAULT,
                           ONIG_ENCODING_ASCII,
                           ONIG_SYNTAX_DEFAULT, &errinfo);
    fprintf(stderr, "number of names: %d\n", onig_number_of_names(match));

    evbase = event_base_new();
    htp    = evhtp_new(evbase, NULL);
    log    = htp_logutil_new("$rhost $host $meth $path");

    evhtp_set_cb(htp, "/", process_request_, log);
    evhtp_enable_flag(htp, EVHTP_FLAG_ENABLE_ALL);

    log_info("Basic server, run: curl http://127.0.0.1:%d/",
            bind__sock_port0_(htp));
    event_base_loop(evbase, 0);
    return 0;
}
