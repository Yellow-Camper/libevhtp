#ifndef __EVHTP_LOG_H__
#define __EVHTP_LOG_H__


/**
 * @brief create a new request-logging context with the format string `format`
 * @note  The following variable definitions are treated as special in the
 * format:
 *    $ua     - the user-agent
 *    $path   - the requested path
 *    $rhost  - the IP address of the request
 *    $meth   - the HTTP method
 *    $ts     - timestamp
 *    $proto  - HTTP proto version
 *    $status - the return status
 *    $ref    - the HTTP referrer
 *    $host   - either the vhost (if defined) or the value of the Host: header
 * All other characters are treated as-is.
 *
 * @param format - format string (see above)
 */
EVHTP_EXPORT void * evhtp_log_new(const char * format);


/**
 * @brief log a HTTP request to a FILE using a compiled format.
 *
 * @param log     - The compiled format (see evhtp_log_new)
 * @param request
 * @param fp
 */
EVHTP_EXPORT void   evhtp_log_request_f(void * log, evhtp_request_t * request, FILE * fp);

#endif

