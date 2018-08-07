#ifndef __EVHTP_LOGUTILS_H__
#define __EVHTP_LOGUTILS_H__

EVHTP_EXPORT void * htp_logutil_new(const char * format);
EVHTP_EXPORT void   htp_log_request(void * logutil, FILE * fp, evhtp_request_t * request);

#endif

