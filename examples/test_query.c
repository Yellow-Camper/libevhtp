#include <stdio.h>
#include <assert.h>

#include "evhtp.h"

struct expected {
    char * key;
    char * val;
};

static int
test_cmp(evhtp_query_t * query, evhtp_kv_t * kvobj, const char * valstr, struct expected * exp) {
    if (!query || !kvobj) {
        return -1;
    }

    if (exp->val == NULL) {
        if (kvobj->val || valstr) {
            return -1;
        }

        return 0;
    }

    if (strcmp(kvobj->val, exp->val)) {
        return -1;
    }

    if (strcmp(valstr, exp->val)) {
        return -1;
    }

    return 0;
}

static int
query_test(const char * raw_query, struct expected expected_data[]) {
    evhtp_query_t   * query;
    struct expected * check;
    int               idx        = 0;
    int               num_errors = 0;

    if (!(query = evhtp_parse_query(raw_query, strlen(raw_query)))) {
        return -1;
    }

    while (1) {
        evhtp_kv_t * kvobj  = NULL;
        const char * valstr = NULL;

        check = &expected_data[idx++];

        if (check == NULL || check->key == NULL) {
            break;
        }

        kvobj  = evhtp_kvs_find_kv(query, check->key);
        valstr = evhtp_kv_find(query, check->key);

        if (test_cmp(query, kvobj, valstr, check) == -1) {
            num_errors += 1;
        }
    }

    return num_errors;
}

static const char    * t1_str   = "notp&ifp=&othernotp;thenp=;key=val";
static const char    * t2_str   = "foo=bar;baz=raz&a=1";

static struct expected t1_exp[] = {
    { "notp",      NULL  },
    { "ifp",       ""    },
    { "othernotp", NULL  },
    { "thenp",     ""    },
    { "key",       "val" },
    { NULL,        NULL  }
};


static struct expected t2_exp[] = {
    { "foo", "bar" },
    { "baz", "raz" },
    { "a",   "1"   },
    { NULL,  NULL  }
};

static void
test(const char * qstr, struct expected exp[]) {
    printf("%-50s %s\n", qstr, query_test(qstr, exp) ? "ERROR" : "OK");
}

int
main(int argc, char ** argv) {
    test(t1_str, t1_exp);
    test(t2_str, t2_exp);

    return 0;
}
