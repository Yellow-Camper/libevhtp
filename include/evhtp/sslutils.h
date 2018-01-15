/**
 * @file sslutils.h
 */

#ifndef __EVHTP_SSLUTILS_H__
#define __EVHTP_SSLUTILS_H__

#include <evhtp/config.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup htp_sslutils SSL utility functions
 */

/**
 * @brief converts the client certificate DNAME information (CN=<cert>, OU=.....)
 * @ingroup htp_sslutils
 *
 * @param ssl the client SSL context
 *
 * @return heap allocated str representation, NULL on error.
 */
EVHTP_EXPORT unsigned char * htp_sslutil_subject_tostr(evhtp_ssl_t * ssl);


/**
 * @brief converts the DN (issuer of cert from the client)
 * @ingroup htp_sslutils
 *
 * @param ssl client SSL context
 *
 * @return heap allocated str representation, NULL on error
 */
EVHTP_EXPORT unsigned char * htp_sslutil_issuer_tostr(evhtp_ssl_t * ssl);


/**
 * @brief converts the `notbefore` date of the cert from the client
 * @ingroup htp_sslutils
 *
 * @param ssl client SSL context
 *
 * @return heap allocated str (YYMMDDhhmmss) of the notbefore, NULL on error.
 */
EVHTP_EXPORT unsigned char * htp_sslutil_notbefore_tostr(evhtp_ssl_t * ssl);


/**
 * @brief converts the `notafter` date of the cert from the client
 * @ingroup htp_sslutils
 *
 * @param ssl ssl client SSL context
 *
 * @return heap allocated str (YYMMDDhhmmss) of notafter, NULL on error.
 */
EVHTP_EXPORT unsigned char * htp_sslutil_notafter_tostr(evhtp_ssl_t * ssl);


/**
 * @brief converts the SHA1 digest in str from the client
 * @ingroup htp_sslutils
 *
 * @param ssl SSL context from client
 *
 * @return NULL on error
 */
EVHTP_EXPORT unsigned char * htp_sslutil_sha1_tostr(evhtp_ssl_t * ssl);

/**
 * @brief convert serial number to string
 * @ingroup htp_sslutils
 *
 * @param ssl SSL context from client
 *
 * @return NULL on error
 */
EVHTP_EXPORT unsigned char * htp_sslutil_serial_tostr(evhtp_ssl_t * ssl);

/**
 * @brief convert the used for this SSL context
 * @ingroup htp_sslutils
 *
 * @param ssl SSL context
 *
 * @return heap allocated cipher str, NULL on error
 */
EVHTP_EXPORT unsigned char * htp_sslutil_cipher_tostr(evhtp_ssl_t * ssl);

/**
 * @brief convert the client cert into a multiline string
 * @ingroup htp_sslutils
 *
 * @param ssl client SSL context
 *
 * @return heap allocated string, NULL on error
 */
EVHTP_EXPORT unsigned char * htp_sslutil_cert_tostr(evhtp_ssl_t * ssl);


/**
 * @brief convert X509 extentions to string
 * @ingroup htp_sslutils
 *
 * @param ssl SSL context
 * @param oid
 *
 * @return
 */
EVHTP_EXPORT unsigned char * htp_sslutil_x509_ext_tostr(evhtp_ssl_t * ssl, const char * oid);


/**
 * @brief convert a string to the proper verify opts
 * @ingroup htp_sslutils
 *
 * @param opts_str ("on" / "optional" / "off" )
 *        where:
 *         "on"       : client must present a valid cert (otherwise rejected)
 *         "off"      : no client cert required at all
 *         "optional" : client MAY present a valid certificate (but not rejected)
 *
 * @note if `opts_str` is NULL, defaults to "off"
 *
 * @return OR'd mask SSL_VERIFY_* flags, -1 on error
 */
EVHTP_EXPORT int htp_sslutil_verify2opts(const char * opts_str);

/*
 * @ingroup htp_sslutils
 * @ {
 */
#define HTP_SSLUTILS_XHDR_SUBJ (1 << 0)
#define HTP_SSLUTILS_XHDR_ISSR (1 << 1)
#define HTP_SSLUTILS_XHDR_NBFR (1 << 2)
#define HTP_SSLUTILS_XHDR_NAFR (1 << 3)
#define HTP_SSLUTILS_XHDR_SERL (1 << 4)
#define HTP_SSLUTILS_XHDR_SHA1 (1 << 5)
#define HTP_SSLUTILS_XHDR_CERT (1 << 6)
#define HTP_SSLUTILS_XHDR_CIPH (1 << 7)
#define HTP_SSLUTILS_XHDR_ALL \
    HTP_SSLUTILS_XHDR_SUBJ    \
    | HTP_SSLUTILS_XHDR_ISSR  \
    | HTP_SSLUTILS_XHDR_NBFR  \
    | HTP_SSLUTILS_XHDR_NAFR  \
    | HTP_SSLUTILS_XHDR_SERL  \
    | HTP_SSLUTILS_XHDR_SHA1  \
    | HTP_SSLUTILS_XHDR_CERT  \
    | HTP_SSLUTILS_XHDR_CIPH
/** @} */

/**
 * @brief add SSL-type X-Header flags to an evhtp_headers_t context
 * @ingroup htp_sslutils
 *
 * @param hdrs headers structure to append into
 * @param ssl  the SSL context
 *        HTP_SSLUTILS_XHDR_SUBJ: `X-SSL-Subject`
 *        HTP_SSLUTILS_XHDR_ISSR: `X-SSL-Issuer`
 *        HTP_SSLUTILS_XHDR_NBFR: `X-SSL-Notbefore`
 *        HTP_SSLUTILS_XHDR_NAFR: `X-SSL-Notafter`
 *        HTP_SSLUTILS_XHDR_SERL: `X-SSL-Serial`
 *        HTP_SSLUTILS_XHDR_CIPH: `X-SSL-Cipher`
 *        HTP_SSLUTILS_XHDR_CERT: `X-SSL-Certificate`
 *        HTP_SSLUTILS_XHDR_SHA1: `X-SSL-SHA1`
 *
 * @param flags flags (See XHDR defines above)
 *
 * @return 0 on success, -1 on error
 */
EVHTP_EXPORT int htp_sslutil_add_xheaders(evhtp_headers_t * hdrs, evhtp_ssl_t * ssl, short flags);

#ifdef __cplusplus
}
#endif

#endif

