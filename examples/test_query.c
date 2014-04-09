#include <stdio.h>
#include <assert.h>
#include <evhtp.h>

int
main(int argc, char ** argv) {
    const char query_raw[] = "notp&ifp=&othernotp;thenp=";
    evhtp_query_t *query = evhtp_parse_query(query_raw, sizeof(query_raw) - 1);

    const char *notp = evhtp_kv_find(query, "notp");
    assert(NULL == notp);
    const char *ifp = evhtp_kv_find(query, "ifp");
    assert(NULL != ifp);
    const char *othernotp = evhtp_kv_find(query, "othernotp");
    assert(NULL == othernotp);
    const char *thenp = evhtp_kv_find(query, "thenp");
    assert(NULL != thenp);

    return 0;
}
