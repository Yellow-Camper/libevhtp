#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "./eutils.h"
#include "internal.h"
#include "evhtp/evhtp.h"

struct reply_ {
    evhtp_request_t * request;
    FILE            * file_desc;
    struct evbuffer * buffer;
};


/* This function is called each time the client has been sent
 * all outstanding data. We use this to send the next part of
 * the file in a chunk at 128 byte increments.
 *
 * When there is no more data to be read from the file, this
 * will send the final chunked reply and free our struct reply_.
 */
static evhtp_res
http__send_chunk_(evhtp_connection_t * conn, void * arg)
{
    struct reply_ * reply = (struct reply_ *)arg;
    char            buf[128];
    size_t          bytes_read;

    /* try to read 128 bytes from the file pointer */
    bytes_read = fread(buf, 1, sizeof(buf), reply->file_desc);

    log_info("Sending %zu bytes", bytes_read);

    if (bytes_read > 0) {
        /* add our data we read from the file into our reply buffer */
        evbuffer_add(reply->buffer, buf, bytes_read);

        /* send the reply buffer as a http chunked message */
        evhtp_send_reply_chunk(reply->request, reply->buffer);

        /* we can now drain our reply buffer as to not be a resource
         * hog.
         */
        evbuffer_drain(reply->buffer, bytes_read);
    }

    /* check if we have read everything from the file */
    if (feof(reply->file_desc)) {
        log_info("Sending last chunk");

        /* now that we have read everything from the file, we must
         * first unset our on_write hook, then inform evhtp to send
         * this message as the final chunk.
         */
        evhtp_connection_unset_hook(conn, evhtp_hook_on_write);
        evhtp_send_reply_chunk_end(reply->request);

        /* we can now free up our little reply_ structure */
        {
            fclose(reply->file_desc);

            evhtp_safe_free(reply->buffer, evbuffer_free);
            evhtp_safe_free(reply, free);
        }
    }

    return EVHTP_RES_OK;
}

static evhtp_res
http__conn_fini_(struct evhtp_connection * c, void * arg)
{
    log_info("hi");
    return EVHTP_RES_OK;
}

/* This function is called when a request has been fully received.
 *
 * This function assumes the `arg` value is the filename that was
 * passed via `evhtp_set_gencb` in `main`.
 *
 * 1. open the file
 * 2. create a `struct reply_`
 * 3. create an evbuffer that we will write into.
 * 4. set a hook to call the function `http__send_chunk_` each
 *    time all data has been sent from the previous write call.
 * 5. start the chunked stream via `evhtp_send_reply_chunk_start`
 */
static void
http__callback_(evhtp_request_t * req, void * arg)
{
    const char    * filename = arg;
    FILE          * file_desc;
    struct reply_ * reply;

    evhtp_assert(arg != NULL);

    /* open up the file as passed to us via evhtp_set_gencb */
    file_desc = fopen(filename, "r");
    evhtp_assert(file_desc != NULL);

    /* create our little internal reply structure which will
     * be used by `http__send_chunk_`
     */
    reply = mm__alloc_(struct reply_, {
        req,
        file_desc,
        evbuffer_new()
    });

    /* here we set a connection hook of the type `evhtp_hook_on_write`
     *
     * this will execute the function `http__send_chunk_` each time
     * all data has been written to the client.
     */
    evhtp_connection_set_hook(req->conn,
        evhtp_hook_on_write,
        http__send_chunk_, reply);

    /* set a hook to be called when the client disconnects */
    evhtp_connection_set_hook(req->conn,
        evhtp_hook_on_connection_fini,
        http__conn_fini_, NULL);

    /* we do not have to start sending data from the file from here -
     * this function will write data to the client, thus when finished,
     * will call our `http__send_chunk_` callback.
     */
    evhtp_send_reply_chunk_start(req, EVHTP_RES_OK);
}

int
main(int argc, char ** argv)
{
    evhtp_t           * htp;
    struct event_base * evbase;

    if (argc < 2) {
        printf("Usage: %s <file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    evbase = event_base_new();
    evhtp_alloc_assert(evbase);

    htp    = evhtp_new(evbase, NULL);
    evhtp_alloc_assert(htp);

    /* here we set our default request response callback, the argument
     * that is passed will be the filename we want to stream to the
     * client in chunked form.
     */
    evhtp_set_gencb(htp, http__callback_, strdup(argv[1]));

    log_info("curl http://127.0.0.1:%d/", bind__sock_port0_(htp));

    event_base_loop(evbase, 0);


    return 0;
}
