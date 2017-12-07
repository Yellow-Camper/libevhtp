/**
 * @file sslutils.h
 */

#ifndef __EVHTP_SSLUTILS_H__
#define __EVHTP_SSLUTILS_H__

#include <evhtp/config.h>

#ifdef __cplusplus
extern "C" {
#endif

EVHTP_EXPORT unsigned char * htp_sslutil_subject_tostr(evhtp_ssl_t * ssl);
EVHTP_EXPORT unsigned char * htp_sslutil_issuer_tostr(evhtp_ssl_t * ssl);
EVHTP_EXPORT unsigned char * htp_sslutil_notbefore_tostr(evhtp_ssl_t * ssl);
EVHTP_EXPORT unsigned char * htp_sslutil_notafter_tostr(evhtp_ssl_t * ssl);
EVHTP_EXPORT unsigned char * htp_sslutil_sha1_tostr(evhtp_ssl_t * ssl);
EVHTP_EXPORT unsigned char * htp_sslutil_serial_tostr(evhtp_ssl_t * ssl);
EVHTP_EXPORT unsigned char * htp_sslutil_cipher_tostr(evhtp_ssl_t * ssl);
EVHTP_EXPORT unsigned char * htp_sslutil_cert_tostr(evhtp_ssl_t * ssl);
EVHTP_EXPORT unsigned char * htp_sslutil_x509_ext_tostr(evhtp_ssl_t * ssl, const char * oid);


#ifdef __cplusplus
}
#endif

#endif

