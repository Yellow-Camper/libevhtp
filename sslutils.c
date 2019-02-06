#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include "evhtp/config.h"
#include "evhtp/evhtp.h"
#include "evhtp/sslutils.h"
#include "internal.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_get0_notBefore(x) X509_get_notBefore(x)
#define X509_get0_notAfter(x) X509_get_notAfter(x)
#endif

unsigned char *
htp_sslutil_subject_tostr(evhtp_ssl_t * ssl) {
    unsigned char * subj_str;
    char          * p;
    X509          * cert;
    X509_NAME     * name;

    if (!ssl) {
        return NULL;
    }

    if (!(cert = SSL_get_peer_certificate(ssl))) {
        return NULL;
    }

    if (!(name = X509_get_subject_name(cert))) {
        X509_free(cert);
        return NULL;
    }

    if (!(p = X509_NAME_oneline(name, NULL, 0))) {
        X509_free(cert);
        return NULL;
    }

    subj_str = (unsigned char *)strdup(p);

    OPENSSL_free(p);
    X509_free(cert);

    return subj_str;
}

unsigned char *
htp_sslutil_issuer_tostr(evhtp_ssl_t * ssl) {
    X509          * cert;
    X509_NAME     * name;
    char          * p;
    unsigned char * issr_str;

    if (!ssl) {
        return NULL;
    }

    if (!(cert = SSL_get_peer_certificate(ssl))) {
        return NULL;
    }

    if (!(name = X509_get_issuer_name(cert))) {
        X509_free(cert);
        return NULL;
    }

    if (!(p = X509_NAME_oneline(name, NULL, 0))) {
        X509_free(cert);
        return NULL;
    }

    issr_str = (unsigned char *)strdup(p);

    OPENSSL_free(p);
    X509_free(cert);

    return issr_str;
}

unsigned char *
htp_sslutil_notbefore_tostr(evhtp_ssl_t * ssl) {
    BIO             * bio;
    X509            * cert;
    const ASN1_TIME * time;
    size_t            len;
    unsigned char   * time_str;

    if (!ssl) {
        return NULL;
    }

    if (!(cert = SSL_get_peer_certificate(ssl))) {
        return NULL;
    }

    if (!(time = X509_get0_notBefore(cert))) {
        X509_free(cert);
        return NULL;
    }

    if (!(bio = BIO_new(BIO_s_mem()))) {
        X509_free(cert);
        return NULL;
    }

    if (!ASN1_TIME_print(bio, time)) {
        BIO_free(bio);
        X509_free(cert);
        return NULL;
    }

    if ((len = BIO_pending(bio)) == 0) {
        BIO_free(bio);
        X509_free(cert);
        return NULL;
    }

    if (!(time_str = calloc(len + 1, 1))) {
        return NULL;
    }

    BIO_read(bio, time_str, len);

    BIO_free(bio);
    X509_free(cert);

    return time_str;
} /* htp_sslutil_notbefore_tostr */

unsigned char *
htp_sslutil_notafter_tostr(evhtp_ssl_t * ssl) {
    BIO             * bio;
    X509            * cert;
    const ASN1_TIME * time;
    size_t            len;
    unsigned char   * time_str;

    if (!ssl) {
        return NULL;
    }

    if (!(cert = SSL_get_peer_certificate(ssl))) {
        return NULL;
    }

    if (!(time = X509_get0_notAfter(cert))) {
        X509_free(cert);
        return NULL;
    }

    if (!(bio = BIO_new(BIO_s_mem()))) {
        X509_free(cert);
        return NULL;
    }

    if (!ASN1_TIME_print(bio, time)) {
        BIO_free(bio);
        X509_free(cert);
        return NULL;
    }

    if ((len = BIO_pending(bio)) == 0) {
        BIO_free(bio);
        X509_free(cert);
        return NULL;
    }

    if (!(time_str = calloc(len + 1, 1))) {
        return NULL;
    }

    BIO_read(bio, time_str, len);

    BIO_free(bio);
    X509_free(cert);

    return time_str;
} /* htp_sslutil_notafter_tostr */

unsigned char *
htp_sslutil_sha1_tostr(evhtp_ssl_t * ssl) {
    const EVP_MD  * md_alg;
    X509          * cert;
    unsigned int    n;
    unsigned char   md[EVP_MAX_MD_SIZE];
    unsigned char * buf = NULL;
    size_t          offset;
    size_t          nsz;
    int             sz;
    int             i;

    if (!ssl) {
        return NULL;
    }

    md_alg = EVP_sha1();

    if (!md_alg) {
        return NULL;
    }

    if (!(cert = SSL_get_peer_certificate(ssl))) {
        return NULL;
    }

    n   = 0;
    if (!X509_digest(cert, md_alg, md, &n)) {
        return NULL;
    }

    nsz = 3 * n + 1;
    buf = (unsigned char *)calloc(nsz, 1);
    if (buf) {
        offset = 0;
        for (i = 0; i < n; i++) {
            sz      = snprintf(buf + offset, nsz - offset, "%02X%c", md[i], (i + 1 == n) ? 0 : ':');
            offset += sz;

            if (sz < 0 || offset >= nsz) {
                free(buf);
                buf = NULL;
                break;
            }
        }
    }

    X509_free(cert);

    return buf;
} /* htp_sslutil_sha1_tostr */

unsigned char *
htp_sslutil_serial_tostr(evhtp_ssl_t * ssl) {
    BIO           * bio;
    X509          * cert;
    size_t          len;
    unsigned char * ser_str;

    if (!ssl) {
        return NULL;
    }

    if (!(cert = SSL_get_peer_certificate(ssl))) {
        return NULL;
    }

    if (!(bio = BIO_new(BIO_s_mem()))) {
        X509_free(cert);
        return NULL;
    }

    i2a_ASN1_INTEGER(bio, X509_get_serialNumber(cert));

    if ((len = BIO_pending(bio)) == 0) {
        BIO_free(bio);
        X509_free(cert);
        return NULL;
    }

    if (!(ser_str = calloc(len + 1, 1))) {
        return NULL;
    }

    BIO_read(bio, ser_str, len);

    X509_free(cert);
    BIO_free(bio);

    return ser_str;
} /* htp_sslutil_serial_tostr */

unsigned char *
htp_sslutil_cipher_tostr(evhtp_ssl_t * ssl) {
    const SSL_CIPHER * cipher;
    const char       * p;
    unsigned char    * cipher_str;

    if (!ssl) {
        return NULL;
    }

    if (!(cipher = SSL_get_current_cipher(ssl))) {
        return NULL;
    }

    if (!(p = SSL_CIPHER_get_name(cipher))) {
        return NULL;
    }

    cipher_str = (unsigned char *)strdup(p);

    return cipher_str;
}

unsigned char *
htp_sslutil_cert_tostr(evhtp_ssl_t * ssl) {
    X509          * cert;
    BIO           * bio;
    unsigned char * raw_cert_str;
    unsigned char * cert_str;
    unsigned char * p;
    size_t          raw_cert_len;
    size_t          cert_len;
    int             i;

    if (!ssl) {
        return NULL;
    }

    if (!(cert = SSL_get_peer_certificate(ssl))) {
        return NULL;
    }

    if (!(bio = BIO_new(BIO_s_mem()))) {
        X509_free(cert);
        return NULL;
    }

    if (!PEM_write_bio_X509(bio, cert)) {
        BIO_free(bio);
        X509_free(cert);

        return NULL;
    }

    raw_cert_len = BIO_pending(bio);
    raw_cert_str = calloc(raw_cert_len + 1, 1);

    BIO_read(bio, raw_cert_str, raw_cert_len);

    cert_len     = raw_cert_len - 1;

    for (i = 0; i < raw_cert_len - 1; i++) {
        if (raw_cert_str[i] == '\n') {
            /*
             * \n's will be converted to \r\n\t, so we must reserve
             * enough space for that much data.
             */
            cert_len += 2;
        }
    }

    /* 2 extra chars, one for possible last char (if not '\n'), and one for NULL terminator */
    cert_str = calloc(cert_len + 2, 1);
    p        = cert_str;

    for (i = 0; i < raw_cert_len - 1; i++) {
        if (raw_cert_str[i] == '\n') {
            *p++ = '\r';
            *p++ = '\n';
            *p++ = '\t';
        } else {
            *p++ = raw_cert_str[i];
        }
    }

    /* Don't assume last character is '\n' */
    if (raw_cert_str[i] != '\n') {
        *p++ = raw_cert_str[i];
    }

    BIO_free(bio);
    X509_free(cert);
    free(raw_cert_str);

    return cert_str;
} /* htp_sslutil_cert_tostr */

unsigned char *
htp_sslutil_x509_ext_tostr(evhtp_ssl_t * ssl, const char * oid) {
    unsigned char       * ext_str;
    X509                * cert;
    ASN1_OBJECT         * oid_obj;
    int                   oid_pos;
    X509_EXTENSION      * ext;
    ASN1_OCTET_STRING   * octet;
    const unsigned char * octet_data;
    long                  xlen;
    int                   xtag;
    int                   xclass;

    if (!ssl) {
        return NULL;
    }

    if (!(cert = SSL_get_peer_certificate(ssl))) {
        return NULL;
    }

    if (!(oid_obj = OBJ_txt2obj(oid, 1))) {
        X509_free(cert);
        return NULL;
    }

    ext_str = NULL;
    oid_pos = X509_get_ext_by_OBJ(cert, oid_obj, -1);

    if (!(ext = X509_get_ext(cert, oid_pos))) {
        ASN1_OBJECT_free(oid_obj);
        X509_free(cert);
        return NULL;
    }

    if (!(octet = X509_EXTENSION_get_data(ext))) {
        ASN1_OBJECT_free(oid_obj);
        X509_free(cert);
        return NULL;
    }

    octet_data = octet->data;

    if (ASN1_get_object(&octet_data, &xlen, &xtag, &xclass, octet->length)) {
        ASN1_OBJECT_free(oid_obj);
        X509_free(cert);
        return NULL;
    }

    /* We're only supporting string data. Could optionally add support
     * for encoded binary data */

    if (xlen > 0 && xtag == 0x0C && octet->type == V_ASN1_OCTET_STRING) {
        ext_str = (unsigned char *)strndup((const char *)octet_data, xlen);
    }

    ASN1_OBJECT_free(oid_obj);
    X509_free(cert);

    return ext_str;
} /* htp_sslutil_x509_ext_tostr */

int
htp_sslutil_verify2opts(const char * opts_str) {
    if (!opts_str || !strcasecmp(opts_str, "off")) {
        return SSL_VERIFY_NONE;
    }

    if (!strcasecmp(opts_str, "optional")) {
        return SSL_VERIFY_PEER;
    }

    if (!strcasecmp(opts_str, "on")) {
        return SSL_VERIFY_PEER
               | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }

    return -1;
}

int
htp_sslutil_add_xheaders(evhtp_headers_t * hdrs, evhtp_ssl_t * ssl, short flags) {
    int i;

    if (!hdrs || !ssl) {
        return -1;
    }

    struct {
        const char    * hdr_str;
        short           flag;
        unsigned char * (* convfn)(evhtp_ssl_t *);
    } ssl_x_hdrs_[] = {
        { "X-SSL-Subject",     HTP_SSLUTILS_XHDR_SUBJ, htp_sslutil_subject_tostr   },
        { "X-SSL-Issuer",      HTP_SSLUTILS_XHDR_ISSR, htp_sslutil_issuer_tostr    },
        { "X-SSL-Notbefore",   HTP_SSLUTILS_XHDR_NBFR, htp_sslutil_notbefore_tostr },
        { "X-SSL-Notafter",    HTP_SSLUTILS_XHDR_NAFR, htp_sslutil_notafter_tostr  },
        { "X-SSL-Serial",      HTP_SSLUTILS_XHDR_SERL, htp_sslutil_serial_tostr    },
        { "X-SSL-Cipher",      HTP_SSLUTILS_XHDR_CIPH, htp_sslutil_cipher_tostr    },
        { "X-SSL-Certificate", HTP_SSLUTILS_XHDR_CERT, htp_sslutil_cert_tostr      },
        { "X-SSL-SHA1",        HTP_SSLUTILS_XHDR_SHA1, htp_sslutil_sha1_tostr      },
        { NULL,                0,                      NULL                        }
    };

    /* remove all of the current x- headers if present */
    evhtp_kv_rm_and_free(hdrs, evhtp_kvs_find_kv(hdrs, "X-SSL-Subject"));
    evhtp_kv_rm_and_free(hdrs, evhtp_kvs_find_kv(hdrs, "X-SSL-Issuer"));
    evhtp_kv_rm_and_free(hdrs, evhtp_kvs_find_kv(hdrs, "X-SSL-Notbefore"));
    evhtp_kv_rm_and_free(hdrs, evhtp_kvs_find_kv(hdrs, "X-SSL-Notafter"));
    evhtp_kv_rm_and_free(hdrs, evhtp_kvs_find_kv(hdrs, "X-SSL-Serial"));
    evhtp_kv_rm_and_free(hdrs, evhtp_kvs_find_kv(hdrs, "X-SSL-Cipher"));
    evhtp_kv_rm_and_free(hdrs, evhtp_kvs_find_kv(hdrs, "X-SSL-Certificate"));

    if (flags == 0) {
        return 0;
    }

    /* iterate over our ssl_x_hdrs_ struct array, compare the flags,
     * and if a xhdr flag is set, run the proper *_tostr function and
     * append it to the `hdrs` passed to this function.
     */
    for (i = 0; ssl_x_hdrs_[i].hdr_str; i++) {
        char * o_str = NULL;

        if (flags & ssl_x_hdrs_[i].flag) {
            if ((o_str = (ssl_x_hdrs_[i].convfn)(ssl))) {
                evhtp_headers_add_header(
                    hdrs,
                    evhtp_header_new(ssl_x_hdrs_[i].hdr_str, o_str, 0, 1));

                evhtp_safe_free(o_str, free);
            }
        }
    }

    return 0;
} /* htp_sslutil_add_xheaders */
