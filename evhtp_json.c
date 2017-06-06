
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>


#include "evhtp_heap.h"
#include "evhtp_json.h"

enum evhtp_j_state {
    evhtp_j_s_start = 0,
    evhtp_j_s_end
};

enum evhtp_j_arr_state {
    evhtp_j_arr_s_val = 0,
    evhtp_j_arr_s_comma,
    evhtp_j_arr_s_end
};

enum evhtp_j_obj_state {
    evhtp_j_obj_s_key = 0,
    evhtp_j_obj_s_delim,
    evhtp_j_obj_s_val,
    evhtp_j_obj_s_comma,
    evhtp_j_obj_s_end
};

typedef enum evhtp_j_state     evhtp_j_state;
typedef enum evhtp_j_arr_state evhtp_j_arr_state;
typedef enum evhtp_j_obj_state evhtp_j_obj_state;

static __thread void * __js_heap = NULL;

struct evhtp_json_s {
    evhtp_json_vtype type;
    union {
        evhtp_kvmap * object;
        evhtp_tailq * array;
        char        * string;
        unsigned int  number;
        bool          boolean;
    };

    size_t slen;
    void   (* freefn)(void *);
};

#define j_type_(j) (evhtp_likely(j) ? j->type : -1)

evhtp_json_vtype
evhtp_json_get_type(evhtp_json * js) {
    if (evhtp_unlikely(js == NULL)) {
        return -1;
    } else {
        return js->type;
    }
}

ssize_t
evhtp_json_get_size(evhtp_json * js) {
    if (evhtp_unlikely(js == NULL)) {
        return -1;
    }

    if (js == NULL) {
        return -1;
    }

    switch (j_type_(js)) {
        case evhtp_json_vtype_string:
            return (ssize_t)js->slen;
        case evhtp_json_vtype_array:
            return evhtp_tailq_size(js->array);
        case evhtp_json_vtype_object:
            return evhtp_kvmap_get_size(js->object);
        default:
            return 0;
    }

    return 0;
}

evhtp_kvmap *
evhtp_json_get_object(evhtp_json * js) {
    if (evhtp_unlikely(js == NULL)) {
        return NULL;
    }

    if (evhtp_unlikely(j_type_(js) != evhtp_json_vtype_object)) {
        return NULL;
    } else {
        return js->object;
    }
}

evhtp_tailq *
evhtp_json_get_array(evhtp_json * js) {
    if (js == NULL) {
        return NULL;
    }

    if (evhtp_unlikely(j_type_(js) != evhtp_json_vtype_array)) {
        return NULL;
    }

    return js->array;
}

unsigned int
evhtp_json_get_number(evhtp_json * js) {
    if (js == NULL) {
        return 0;
    }

    if (evhtp_unlikely(j_type_(js) != evhtp_json_vtype_number)) {
        return 0;
    } else {
        return js->number;
    }
}

const char *
evhtp_json_get_string(evhtp_json * js) {
    if (evhtp_unlikely(js == NULL)) {
        return NULL;
    }

    if (evhtp_likely(j_type_(js) == evhtp_json_vtype_string)) {
        return js->string;
    } else {
        return NULL;
    }
}

bool
evhtp_json_get_boolean(evhtp_json * js) {
    if (js == NULL) {
        return false;
    }

    if (evhtp_unlikely(j_type_(js) != evhtp_json_vtype_bool)) {
        return false;
    } else {
        return js->boolean;
    }
}

char
evhtp_json_get_null(evhtp_json * js) {
    if (js == NULL) {
        return -1;
    }

    if (evhtp_unlikely(j_type_(js) != evhtp_json_vtype_null)) {
        return -1;
    } else {
        return 1;
    }
}

static evhtp_json *
j_new_(evhtp_json_vtype type) {
    evhtp_json * evhtp_j;

    if (evhtp_unlikely(__js_heap == NULL)) {
        __js_heap = evhtp_heap_new(sizeof(evhtp_json), 1024);
    }

    evhtp_j         = evhtp_heap_alloc(__js_heap);
    evhtp_alloc_assert(evhtp_j);

    evhtp_j->type   = type;
    evhtp_j->freefn = NULL;
    return evhtp_j;
}

static evhtp_json *
j_object_new_(void) {
    evhtp_json * js;

    if (!(js = j_new_(evhtp_json_vtype_object))) {
        return NULL;
    }

    js->object = evhtp_kvmap_new(10);
    js->freefn = (void (*))evhtp_kvmap_free;

    return js;
}

static inline evhtp_json *
j_array_new_(void) {
    evhtp_json * js;

    if (!(js = j_new_(evhtp_json_vtype_array))) {
        return NULL;
    }

    js->array  = evhtp_tailq_new();
    js->freefn = (void (*))evhtp_tailq_free;

    return js;
}

static evhtp_json *
j_string_new_(const char * str, size_t slen) {
    evhtp_json * js;

    js = j_new_(evhtp_json_vtype_string);
    evhtp_alloc_assert(js);

    if (evhtp_unlikely(str == NULL || slen == 0)) {
        slen = 0;
    }

    js->string       = malloc(slen + 1);
    evhtp_alloc_assert(js->string);

    js->string[slen] = '\0';

    memcpy(js->string, str, slen);

    js->slen         = slen;
    js->freefn       = free;

    return js;
}

static evhtp_json *
j_number_new_(unsigned int num) {
    evhtp_json * js;

    js         = j_new_(evhtp_json_vtype_number);
    js->number = num;

    return js;
}

static evhtp_json *
j_boolean_new_(bool boolean) {
    evhtp_json * js;

    js          = j_new_(evhtp_json_vtype_bool);
    js->boolean = boolean;

    return js;
}

static evhtp_json *
j_null_new_(void) {
    return j_new_(evhtp_json_vtype_null);
}

static int
j_object_add_(evhtp_json * dst, const char * key, evhtp_json * val) {
    if (evhtp_unlikely(j_type_(dst) != evhtp_json_vtype_object)) {
        return -1;
    }

    if (!evhtp_kvmap_add(dst->object, key, val, (void (*))evhtp_json_free)) {
        return -1;
    }

    return 0;
}

static int
j_object_add_klen_(evhtp_json * dst, const char * key, size_t klen, evhtp_json * val) {
    if (evhtp_unlikely(j_type_(dst) != evhtp_json_vtype_object)) {
        return -1;
    }

    if (!evhtp_kvmap_add_wklen(dst->object,
                               key, klen, val, (void (*))evhtp_json_free)) {
        return -1;
    }

    return 0;
}

static int
j_array_add_(evhtp_json * dst, evhtp_json * src) {
    if (evhtp_unlikely(j_type_(dst) != evhtp_json_vtype_array)) {
        return -1;
    }

    if (!evhtp_tailq_append(dst->array, src, 1, (void (*))evhtp_json_free)) {
        return -1;
    }

    return 0;
}

evhtp_json *
evhtp_json_parse_string(const char * data, size_t len, size_t * n_read) {
    unsigned char ch;
    size_t        i;
    size_t        buflen;
    char          buf[len + 128];
    int           buf_idx;
    int           escaped;
    bool          error;
    evhtp_json  * js;

    if (!data || !len || *data != '"') {
        /* *n_read = 0; */
        return NULL;
    }

    escaped = 0;
    buf_idx = 0;
    error   = false;
    js      = NULL;
    buflen  = len + 128;

    len--;
    data++;

    for (i = 0; i < len; i++) {
        if (buf_idx >= buflen) {
            error = true;
            errno = ENOBUFS;
            goto end;
        }

        ch = data[i];

        if (!evhtp_isascii(ch)) {
            error = true;
            goto end;
        }

        if (escaped) {
            switch (ch) {
                case '"':
                case '/':
                case 'b':
                case 'f':
                case 'n':
                case 'r':
                case 't':
                case '\\':
                    escaped        = 0;
                    buf[buf_idx++] = ch;
                    break;
                default:
                    error          = true;
                    goto end;
            }
            continue;
        }

        if (ch == '\\') {
            escaped = 1;
            continue;
        }

        if (ch == '"') {
            js = j_string_new(buf, buf_idx);
            i += 1;
            break;
        }

        buf[buf_idx++] = ch;
    }

end:
    *n_read += i;

    if (error == true) {
        evhtp_safe_free(js, evhtp_json_free);
        return NULL;
    }

    return js;
} /* evhtp_json_parse_string */

inline evhtp_json *
evhtp_json_parse_key(const char * data, size_t len, size_t * n_read) {
    return evhtp_json_parse_string(data, len, n_read);
}

evhtp_json *
evhtp_json_parse_number(const char * data, size_t len, size_t * n_read) {
    unsigned char ch;
    char          buf[len];
    int           buf_idx;
    size_t        i;
    evhtp_json  * js;

    if (!data || !len) {
        return NULL;
    }

    js      = NULL;
    buf_idx = 0;

    memset(buf, 0, sizeof(buf));

    for (i = 0; i < len; i++) {
        ch = data[i];

        if (!isdigit(ch) || (len == 1 && isdigit(ch))) {
            js = j_number_new((unsigned int)evhtp_atoi(buf, buf_idx));
            break;
        }

        buf[buf_idx++] = ch;
    }

    *n_read += (len == 1) ? 1 : i - 1;

    return js;
}

#define J_TRUE_CMP   0x657572
#define J_FALSE_CMP  0x65736c61
#define J_TRUE_MASK  0xFFFFFF
#define J_FALSE_MASK 0xFFFFFFFF

inline evhtp_json *
evhtp_json_parse_boolean(const char * data, size_t len, size_t * n_read) {
    evhtp_json * js;

    if (evhtp_unlikely(len < 4)) {
        /* need at LEAST 'true' */
        return NULL;
    }

    js = NULL;

    /* here we cast our data string to an integer, mask it by the
     * number of words we want to see, then match the integer version
     * of the string.
     */
    switch (*data) {
        case 't':
            if ((*((uint32_t *)(data + 1)) & J_TRUE_MASK) == J_TRUE_CMP) {
                *n_read += 3;
                js       = j_boolean_new(true);
            }

            break;
        case 'f':
            if (len < 5) {
                return NULL;
            }

            if ((*((uint32_t *)(data + 1)) & J_FALSE_MASK) == J_FALSE_CMP) {
                *n_read += 4;
                js       = j_boolean_new(false);
            }

            break;
        default:
            return NULL;
    } /* switch */

    return js;
}     /* evhtp_json_parse_boolean */

evhtp_json *
evhtp_json_parse_null(const char * data, size_t len, size_t * n_read) {
    if (len < 4) {
        return NULL;
    }

    if (!evhtp_str30_cmp(data, 'n', 'u', 'l', 'l')) {
        return NULL;
    }

    *n_read += 4;

    return j_null_new();
}

evhtp_json *
evhtp_json_parse_value(const char * data, size_t len, size_t * n_read) {
    if (data == NULL || len == 0) {
        /* *n_read = 0; */
        return NULL;
    }

    switch (data[0]) {
        case '"':
            return evhtp_json_parse_string(data, len, n_read);
        case '{':
            return evhtp_json_parse_object(data, len, n_read);
        case '[':
            return evhtp_json_parse_array(data, len, n_read);
        default:
            if (isdigit(data[0])) {
                return evhtp_json_parse_number(data, len, n_read);
            }

            switch (*data) {
                case 't':
                case 'f':
                    return evhtp_json_parse_boolean(data, len, n_read);
                case 'n':
                    return evhtp_json_parse_null(data, len, n_read);
            }
    } /* switch */

    /* *n_read = 0; */
    return NULL;
}

evhtp_json *
evhtp_json_parse_array(const char * data, size_t len, size_t * n_read) {
    unsigned char     ch;
    unsigned char     end_ch;
    size_t            i;
    bool              error;
    size_t            b_read;
    evhtp_j_arr_state state;
    evhtp_json      * js;


    if (!data || !len || *data != '[') {
        /* *n_read = 0; */
        return NULL;
    }

    data++;
    len--;

    js     = j_array_new_();
    state  = evhtp_j_arr_s_val;
    error  = false;
    b_read = 0;
    end_ch = 0;

    for (i = 0; i < len; i++) {
        evhtp_json * val;

        ch = data[i];

        if (isspace(ch)) {
            continue;
        }

        switch (state) {
            case evhtp_j_arr_s_val:
                if (ch == ']') {
                    end_ch = ch;
                    state  = evhtp_j_arr_s_end;
                    break;
                }

                if (!(val = evhtp_json_parse_value(&data[i], (len - i), &b_read))) {
                    error = true;
                    goto end;
                }

                i     += b_read;
                b_read = 0;

                j_array_add(js, val);

                state  = evhtp_j_arr_s_comma;

                if ((i + 1) == len) {
                    end_ch = data[i];
                }

                break;
            case evhtp_j_arr_s_comma:
                switch (ch) {
                    case ',':
                        state  = evhtp_j_arr_s_val;
                        break;
                    case ']':
                        end_ch = ch;
                        state  = evhtp_j_arr_s_end;
                        break;
                    default:
                        error  = true;
                        goto end;
                }
                break;
            case evhtp_j_arr_s_end:
                goto end;
        } /* switch */
    }
end:
    *n_read += i;

    if ((end_ch != ']' || error == true)) {
        evhtp_safe_free(js, evhtp_json_free);
        return NULL;
    }

    return js;
} /* evhtp_json_parse_array */

evhtp_json *
evhtp_json_parse_object(const char * data, size_t len, size_t * n_read) {
    unsigned char     ch;
    unsigned char     end_ch;
    size_t            i;
    evhtp_json      * js;
    evhtp_json      * key;
    evhtp_json      * val;
    evhtp_j_obj_state state;
    bool              error;
    size_t            b_read;

    if (*data != '{') {
        /* *n_read = 0; */
        return NULL;
    }

    state  = evhtp_j_obj_s_key;
    js     = j_object_new_();
    key    = NULL;
    val    = NULL;
    error  = false;
    b_read = 0;
    end_ch = 0;

    data++;
    len--;

    for (i = 0; i < len; i++) {
        ch = data[i];

        if (isspace(ch)) {
            continue;
        }

        switch (state) {
            case evhtp_j_obj_s_key:
                if (ch == '}') {
                    end_ch = ch;
                    state  = evhtp_j_obj_s_end;
                    break;
                }

                if (!(key = evhtp_json_parse_key(&data[i], (len - i), &b_read))) {
                    error = true;
                    i    += b_read;
                    goto end;
                }

                i     += b_read;
                b_read = 0;
                state  = evhtp_j_obj_s_delim;
                break;
            case evhtp_j_obj_s_delim:
                if (ch != ':') {
                    error = true;
                    goto end;
                }

                state = evhtp_j_obj_s_val;
                break;

            case evhtp_j_obj_s_val:
                if (!(val = evhtp_json_parse_value(&data[i], (len - i), &b_read))) {
                    error = true;
                    i    += b_read;
                    goto end;
                }

                i     += b_read;
                b_read = 0;

                j_object_add_(js, key->string, val);

                evhtp_safe_free(key, evhtp_json_free);

                key   = NULL;
                state = evhtp_j_obj_s_comma;

                break;

            case evhtp_j_obj_s_comma:
                switch (ch) {
                    case ',':
                        state  = evhtp_j_obj_s_key;
                        break;
                    case '}':
                        end_ch = ch;
                        state  = evhtp_j_obj_s_end;
                        break;
                    default:
                        error  = true;
                        goto end;
                }
                break;
            case evhtp_j_obj_s_end:
                goto end;
        } /* switch */
    }

end:
    *n_read += i;

    evhtp_safe_free(key, evhtp_json_free);

    if ((end_ch != '}' || error == true)) {
        evhtp_safe_free(js, evhtp_json_free);
        return NULL;
    }

    return js;
} /* evhtp_json_parse_object */

evhtp_json *
evhtp_json_parse_buf(const char * data, size_t len, size_t * n_read) {
    unsigned char ch;
    size_t        b_read;
    size_t        i;
    evhtp_json  * js;
    evhtp_j_state state;

    js     = NULL;
    b_read = 0;
    state  = evhtp_j_s_start;

    for (i = 0; i < len; i++) {
        ch = data[i];

        if (isspace(ch)) {
            continue;
        }

        switch (state) {
            case evhtp_j_s_start:
                switch (ch) {
                    case '{':
                        if (!(js = evhtp_json_parse_object(&data[i], (len - i), &b_read))) {
                            *n_read += b_read;
                            return NULL;
                        }

                        i     += b_read;
                        b_read = 0;
                        break;
                    case '[':
                        if (!(js = evhtp_json_parse_array(&data[i], (len - i), &b_read))) {
                            *n_read += b_read;
                            return NULL;
                        }

                        i       += b_read;
                        b_read   = 0;
                        break;
                    default:
                        *n_read += i;
                        return NULL;
                } /* switch */

                state = evhtp_j_s_end;
                break;
            case evhtp_j_s_end:
                break;
        }         /* switch */
    }

    *n_read += i;

    return js;
}         /* evhtp_json_parse_buf */

evhtp_json *
evhtp_json_parse_file(const char * filename, size_t * bytes_read) {
    evhtp_json * json   = NULL;
    FILE       * fp     = NULL;
    char       * buf    = NULL;
    size_t       n_read = 0;
    long         file_size;

    if (filename == NULL) {
        return NULL;
    }

    do {
        if (!(fp = fopen(filename, "re"))) {
            break;
        }

        if (fseek(fp, 0L, SEEK_END) == -1) {
            break;
        }

        if ((file_size = ftell(fp)) == -1) {
            break;
        }

        if (fseek(fp, 0L, SEEK_SET) == -1) {
            break;
        }

        /* allocate 1 more than the size, just incase there is not an EOL
         * terminator in the file.
         */
        if (!(buf = calloc(file_size + 1, 1))) {
            break;
        }

        if (fread(buf, 1, file_size, fp) != file_size) {
            break;
        }

        if (buf[file_size] == 0) {
            /* just make sure we have SOME type of EOL terminator by placing a
             * \n in it. */
            buf[file_size] = '\n';
            file_size     += 1;
        }

        if (!(json = evhtp_json_parse_buf(buf, file_size, &n_read))) {
            break;
        }
    } while (0);

    if (fp != NULL) {
        fclose(fp);
    }

    *bytes_read = n_read;

    evhtp_safe_free(buf, free);
    return json;
} /* evhtp_json_parse_file */

void
evhtp_json_free(evhtp_json * js) {
    if (js == NULL) {
        return;
    }

    switch (j_type_(js)) {
        case evhtp_json_vtype_string:
            evhtp_safe_free(js->string, free);
            break;
        case evhtp_json_vtype_object:
            evhtp_safe_free(js->object, evhtp_kvmap_free);
            break;
        case evhtp_json_vtype_array:
            evhtp_safe_free(js->array, evhtp_tailq_free);
            break;
        default:
            break;
    }

    evhtp_heap_free(__js_heap, js);
}

static evhtp_json *
j_array_index_(evhtp_json * array, int offset) {
    evhtp_tailq * list;

    if (!(list = evhtp_json_get_array(array))) {
        return NULL;
    }

    return (evhtp_json *)evhtp_tailq_get_at_index(list, offset);
}

enum path_state {
    path_state_reading_key,
    path_state_reading_array,
    path_state_reading_array_end
};


evhtp_json *
evhtp_json_get_array_index(evhtp_json * array, int offset) {
    if (evhtp_unlikely(array == NULL || offset < 0)) {
        return NULL;
    }

    return j_array_index_(array, offset);
}

evhtp_json *
evhtp_json_path_get(evhtp_json * js, const char * path) {
    char            buf[strlen(path) + 1];
    int             buf_idx;
    evhtp_kvmap   * object;
    evhtp_json    * prev;
    unsigned char   ch;
    size_t          i;
    enum path_state state;


    if (evhtp_unlikely(js == NULL || path == NULL)) {
        return NULL;
    }

    prev    = js;
    object  = NULL;
    buf_idx = 0;
    buf[0]  = '\0';
    state   = path_state_reading_key;

    for (i = 0; i < strlen(path) + 1; i++) {
        ch = path[i];

        switch (state) {
            case path_state_reading_key:
                switch (ch) {
                    case '[':
                        state = path_state_reading_array;
                        break;
                    case '\0':
                    case '.':
                        if (!(object = evhtp_json_get_object(prev))) {
                            return NULL;
                        }

                        if (!(prev = evhtp_kvmap_find(object, buf))) {
                            return NULL;
                        }

                        buf[0]         = '\0';
                        buf_idx        = 0;
                        break;
                    default:
                        buf[buf_idx++] = ch;
                        buf[buf_idx]   = '\0';
                        break;
                } /* switch */
                break;
            case path_state_reading_array:
                switch (ch) {
                    case ']':
                        if (!(prev = j_array_index_(prev, evhtp_atoi(buf, buf_idx)))) {
                            return NULL;
                        }

                        buf[0]         = '\0';
                        buf_idx        = 0;

                        state          = path_state_reading_array_end;
                        break;
                    default:
                        buf[buf_idx++] = ch;
                        buf[buf_idx]   = '\0';
                        break;
                }
                break;
            case path_state_reading_array_end:
                state = path_state_reading_key;
                break;
        } /* switch */

        if (ch == '\0') {
            break;
        }
    }

    return (prev != js) ? prev : NULL;
} /* evhtp_json_path_get */

evhtp_json *
evhtp_json_new_object(void) {
    return j_object_new_();
}

evhtp_json *
evhtp_json_new_array(void) {
    return j_array_new_();
}

evhtp_json *
evhtp_json_string_new(const char * str) {
    return j_string_new_(str, str ? strlen(str) : 0);
}

evhtp_json *
evhtp_json_string_new_len(const char * str, size_t size) {
    return j_string_new_(str, size);
}

evhtp_json *
evhtp_json_number_new(unsigned int num) {
    return j_number_new_(num);
}

evhtp_json *
evhtp_json_boolean_new(bool boolean) {
    return j_boolean_new_(boolean);
}

evhtp_json *
evhtp_json_null_new(void) {
    return j_null_new_();
}

int
evhtp_json_object_add(evhtp_json * obj, const char * key, evhtp_json * val) {
    if (!obj || !key || !val) {
        return -1;
    }

    return j_object_add_(obj, key, val);
}

inline int
evhtp_json_object_add_klen(evhtp_json * obj, const char * k, size_t klen, evhtp_json * v) {
    if (evhtp_unlikely(obj == NULL)) {
        return -1;
    }

    return j_object_add_klen(obj, k, klen, v);
}

int
evhtp_json_array_add(evhtp_json * array, evhtp_json * val) {
    return j_array_add(array, val);
}

int
evhtp_json_add(evhtp_json * obj, const char * key, evhtp_json * val) {
    if (!obj) {
        return -1;
    }

    if (key == NULL) {
        if (j_type_(obj) != evhtp_json_vtype_array) {
            return -1;
        }

        return evhtp_json_array_add(obj, val);
    }

    return evhtp_json_object_add(obj, key, val);
}

struct __jbuf {
    char  * buf;
    size_t  buf_idx;
    size_t  buf_len;
    ssize_t written;
    int     dynamic;
    bool    escape;
};

static int
j_addbuf_(struct __jbuf * jbuf, const char * buf, size_t len) {
    evhtp_assert(jbuf != NULL);

    if (len == 0 || buf == NULL) {
        return 0;
    }

    if ((jbuf->buf_idx + len) > jbuf->buf_len) {
        if (evhtp_unlikely(jbuf->dynamic == 1)) {
            char * n_buf;

            jbuf->buf      = realloc(jbuf->buf, (size_t)(jbuf->buf_len + len + 32));
            evhtp_alloc_assert(jbuf->buf);

            jbuf->buf_len += len + 32;
        } else {
            return -1;
        }
    }

    memcpy(&jbuf->buf[jbuf->buf_idx], buf, len);

    jbuf->buf_idx += len;
    jbuf->written += len;

    return 0;
}

static int
j_addbuf_vprintf_(struct __jbuf * jbuf, const char * fmt, va_list ap) {
    char tmpbuf[jbuf->buf_len - jbuf->buf_idx];
    int  sres;

    evhtp_assert(jbuf != NULL);

    sres = vsnprintf(tmpbuf, sizeof(tmpbuf), fmt, ap);

    if (sres >= sizeof(tmpbuf) || sres < 0) {
        return -1;
    }

    return j_addbuf_(jbuf, tmpbuf, (size_t)sres);
}

static int
j_addbuf_printf_(struct __jbuf * jbuf, const char * fmt, ...) {
    va_list ap;
    int     sres;

    evhtp_assert(jbuf != NULL);

    va_start(ap, fmt);
    {
        sres = j_addbuf_vprintf_j(jbuf, fmt, ap);
    }
    va_end(ap);

    return sres;
}

static const char digits[] =
    "0001020304050607080910111213141516171819"
    "2021222324252627282930313233343536373839"
    "4041424344454647484950515253545556575859"
    "6061626364656667686970717273747576777879"
    "8081828384858687888990919293949596979899";

static int
j_addbuf_number_(struct __jbuf * jbuf, unsigned int num) {
    char     buf[32]; /* 18446744073709551615 64b, 20 characters */
    char   * buffer          = (char *)buf;
    char   * buffer_end      = buffer + 32;
    char   * buffer_end_save = buffer + 32;
    unsigned index;

    evhtp_assert(jbuf != NULL);

    *--buffer_end = '\0';

    while (num >= 100) {
        index         = (num % 100) * 2;

        num          /= 100;

        *--buffer_end = digits[index + 1];
        *--buffer_end = digits[index];
    }

    if (num < 10) {
        *--buffer_end = (char)('0' + num);
    } else {
        index         = (unsigned)(num * 2);

        *--buffer_end = digits[index + 1];
        *--buffer_end = digits[index];
    }

    return j_addbuf_(jbuf, buffer_end, (size_t)(buffer_end_save - buffer_end - 1));
}

static int j_array_to_buffer__(evhtp_json * json, struct __jbuf * jbuf);
static int j_number_to_buffer__(evhtp_json * json, struct __jbuf * jbuf);
static int j_object_to_buffer__(evhtp_json * json, struct __jbuf * jbuf);

static int
j_number_to_buffer_(evhtp_json * json, struct __jbuf * jbuf) {
    if (evhtp_likely(j_type_(json) != evhtp_json_vtype_number)) {
        return -1;
    } else {
        return addbuf__number(jbuf, json->number);
    }
}

static int
j_escape_string_(const char * str, size_t len, struct __jbuf * jbuf) {
    unsigned char ch;
    size_t        i;

    evhtp_assert(jbuf != NULL);

    if (evhtp_unlikely(str == NULL)) {
        return -1;
    }

    for (i = 0; i < len; i++) {
        ch = str[i];

        switch (ch) {
            default:
                if (evhtp_unlikely(addbuf_(jbuf, (const char *)&ch, 1) == -1)) {
                    return -1;
                }
                break;
            case '\n':
                if (evhtp_unlikely(addbuf_(jbuf, "\\n", 2) == -1)) {
                    return -1;
                }
                break;
            case '"':
                if (evhtp_unlikely(addbuf_(jbuf, "\\\"", 2) == -1)) {
                    return -1;
                }
                break;
            case '\t':
                if (evhtp_unlikely(addbuf_(jbuf, "\\t", 2) == -1)) {
                    return -1;
                }
                break;
            case '\r':
                if (evhtp_unlikely(addbuf_(jbuf, "\\r", 2) == -1)) {
                    return -1;
                }
                break;
            case '\\':
                if (evhtp_unlikely(addbuf_(jbuf, "\\\\", 2) == -1)) {
                    return -1;
                }
                break;
        } /* switch */
    }

    return 0;
}         /* j_escape_string */

static int
j_string_to_buffer_(evhtp_json * json, struct __jbuf * jbuf) {
    const char * str;

    if (j_type_(json) != evhtp_json_vtype_string) {
        return -1;
    }

    str = json->string;

    if (evhtp_unlikely(str == NULL)) {
        return -1;
    }

    if (evhtp_unlikely(j_addbuf_(jbuf, "\"", 1) == -1)) {
        return -1;
    }

    if (jbuf->escape == true) {
        if (evhtp_unlikely(j_escape_string_(str, json->slen, jbuf) == -1)) {
            return -1;
        }
    }

    return j_addbuf_(jbuf, "\"", 1);
}

static int
j_boolean_to_buffer_(evhtp_json * json, struct __jbuf * jbuf) {
    if (j_type_(json) != evhtp_json_vtype_bool) {
        return -1;
    }

    return j_addbuf_printf_(jbuf, "%s",
                            evhtp_json_get_boolean(json) == true ? "true" : "false");
}

static int
j_null_to_buffer_(evhtp_json * json, struct __jbuf * jbuf) {
    if (j_type_(json) != evhtp_json_vtype_null) {
        return -1;
    }

    return addbuf__printf(jbuf, "null");
}

static int
j_to_buffer(evhtp_json * json, struct __jbuf * jbuf) {
    switch (j_type_(json)) {
        case evhtp_json_vtype_number:
            return j_number_to_buffer_(json, jbuf);
        case evhtp_json_vtype_array:
            return j_array_to_buffer_(json, jbuf);
        case evhtp_json_vtype_object:
            return j_object_to_buffer_(json, jbuf);
        case evhtp_json_vtype_string:
            return j_string_to_buffer_(json, jbuf);
        case evhtp_json_vtype_bool:
            return j_boolean_to_buffer_(json, jbuf);
        case evhtp_json_vtype_null:
            return j_null_to_buffer_(json, jbuf);
        default:
            return -1;
    }

    return 0;
}

static int
j_array_to_buffer_(evhtp_json * json, struct __jbuf * jbuf) {
    evhtp_tailq      * array;
    evhtp_tailq_elem * elem;
    evhtp_tailq_elem * temp;

    if (j_type_(json) != evhtp_json_vtype_array) {
        return -1;
    }

    array = json->array;

    if (evhtp_unlikely(addbuf_(jbuf, "[", 1) == -1)) {
        return -1;
    }

    for (elem = evhtp_tailq_first(array); elem; elem = temp) {
        evhtp_json * val;

        val = (evhtp_json *)evhtp_tailq_elem_data(elem);
        evhtp_assert(val != NULL);

        if (evhtp_unlikely(j_to_buffer(val, jbuf) == -1)) {
            return -1;
        }

        if ((temp = evhtp_tailq_next(elem))) {
            if (evhtp_unlikely(addbuf_(jbuf, ",", 1) == -1)) {
                return -1;
            }
        }
    }

    if (evhtp_unlikely(addbuf_(jbuf, "]", 1) == -1)) {
        return -1;
    }

    return 0;
}

static int
j_object_to_buffer_(evhtp_json * json, struct __jbuf * jbuf) {
    evhtp_kvmap     * object;
    evhtp_kvmap_ent * ent;
    evhtp_kvmap_ent * temp;

    if (j_type_(json) != evhtp_json_vtype_object) {
        return -1;
    }

    object = json->object;

    if (evhtp_unlikely(addbuf_(jbuf, "{", 1) == -1)) {
        return -1;
    }

    for (ent = evhtp_kvmap_first(object); ent; ent = temp) {
        const char * key;
        evhtp_json * val;

        key = evhtp_kvmap_ent_key(ent);
        evhtp_assert(key != NULL);

        val = (evhtp_json *)evhtp_kvmap_ent_val(ent);
        evhtp_assert(val != NULL);

        if (evhtp_unlikely(addbuf_(jbuf, "\"", 1) == -1)) {
            return -1;
        }

        if (evhtp_unlikely(addbuf_(jbuf, key, evhtp_kvmap_ent_get_klen(ent)) == -1)) {
            return -1;
        }

        if (evhtp_unlikely(addbuf_(jbuf, "\":", 2) == -1)) {
            return -1;
        }

        if (evhtp_unlikely(j_to_buffer(val, jbuf) == -1)) {
            return -1;
        }

        if ((temp = evhtp_kvmap_next(ent))) {
            if (evhtp_unlikely(addbuf_(jbuf, ",", 1) == -1)) {
                return -1;
            }
        }
    }

    if (evhtp_unlikely(addbuf_(jbuf, "}", 1) == -1)) {
        return -1;
    }

    return 0;
} /* j_object_to_buffer_ */

ssize_t
_evhtp_json_to_buffer(evhtp_json * json, char * buf, size_t buf_len, struct __jbuf * jbuf) {
    if (evhtp_unlikely(!json || !buf)) {
        return -1;
    }

    if (evhtp_unlikely(j_to_buffer(json, jbuf) == -1)) {
        return -1;
    }

    return jbuf->written;
}

ssize_t
evhtp_json_to_buffer(evhtp_json * json, char * buf, size_t buf_len) {
    struct __jbuf jbuf = {
        .buf     = buf,
        .buf_idx = 0,
        .written = 0,
        .buf_len = buf_len,
        .dynamic = 0,
        .escape  = true
    };

    if (evhtp_unlikely(j_to_buffer(json, &jbuf) == -1)) {
        return -1;
    }

    return jbuf.written;
}

ssize_t
evhtp_json_to_buffer_nescp(evhtp_json * json, char * buf, size_t buf_len) {
    struct __jbuf jbuf = {
        .buf     = buf,
        .buf_idx = 0,
        .written = 0,
        .buf_len = buf_len,
        .dynamic = 0,
        .escape  = false
    };

    if (evhtp_unlikely(j_to_buffer(json, &jbuf) == -1)) {
        return -1;
    }

    return jbuf.written;
}

char *
evhtp_json_to_buffer_alloc(evhtp_json * json, size_t * len) {
    struct __jbuf jbuf = {
        .buf     = NULL,
        .buf_idx = 0,
        .written = 0,
        .buf_len = 0,
        .dynamic = 1,
        .escape  = true
    };

    if (!json || !len) {
        return NULL;
    }

    if (j_to_buffer(json, &jbuf) == -1) {
        evhtp_safe_free(jbuf.buf, free);
        return NULL;
    }

    *len = jbuf.written;

    return jbuf.buf;
}

static inline int j_compare_(evhtp_json * j1, evhtp_json * j2, evhtp_json_key_filtercb cb);

static inline int
j_number_compare_(evhtp_json * j1, evhtp_json * j2, evhtp_json_key_filtercb cb) {
    if (j1 == NULL || j2 == NULL) {
        return -1;
    }

    if (j_type_(j1) != evhtp_json_vtype_number) {
        return -1;
    }

    if (j_type_(j2) != evhtp_json_vtype_number) {
        return -1;
    }

    if (evhtp_json_get_number(j1) != evhtp_json_get_number(j2)) {
        return -1;
    }

    return 0;
}

static inline int
j_array_compare_(evhtp_json * j1, evhtp_json * j2, evhtp_json_key_filtercb cb) {
    evhtp_tailq      * j1_array;
    evhtp_tailq      * j2_array;
    evhtp_tailq_elem * elem;
    evhtp_tailq_elem * temp;
    int                idx;

    if (j1 == NULL || j2 == NULL) {
        return -1;
    }

    if (!(j1_array = evhtp_json_get_array(j1))) {
        return -1;
    }

    if (!(j2_array = evhtp_json_get_array(j2))) {
        return -1;
    }

    idx = 0;

    for (elem = evhtp_tailq_first(j1_array); elem; elem = temp) {
        evhtp_json * j1_val;
        evhtp_json * j2_val;

        j1_val = (evhtp_json *)evhtp_tailq_elem_data(elem);
        j2_val = (evhtp_json *)evhtp_tailq_get_at_index(j2_array, idx);

        if (j1_val && !j2_val) {
            return -1;
        }

        if (j2_val && !j1_val) {
            return -1;
        }

        if (j_compare_(j1_val, j2_val, cb) == -1) {
            return -1;
        }

        idx += 1;

        temp = evhtp_tailq_next(elem);
    }

    return 0;
} /* j_array_compare_ */

static int
j_object_compare_(evhtp_json * j1, evhtp_json * j2, evhtp_json_key_filtercb cb) {
    evhtp_kvmap     * j1_map;
    evhtp_kvmap     * j2_map;
    evhtp_kvmap_ent * ent;
    evhtp_kvmap_ent * temp;

    if (j1 == NULL || j2 == NULL) {
        return -1;
    }

    if (!(j1_map = evhtp_json_get_object(j1))) {
        return -1;
    }

    if (!(j2_map = evhtp_json_get_object(j2))) {
        return -1;
    }

    for (ent = evhtp_kvmap_first(j1_map); ent; ent = temp) {
        const char * key;
        evhtp_json * j1_val;
        evhtp_json * j2_val;

        if (!(key = evhtp_kvmap_ent_key(ent))) {
            return -1;
        }

        if (!(j1_val = (evhtp_json *)evhtp_kvmap_ent_val(ent))) {
            return -1;
        }

        if (cb && (cb)(key, j1_val) == 1) {
            /* the key filter callback returned 1, which means we can ignore the
             * comparison of this field.
             */
            temp = evhtp_kvmap_next(ent);
            continue;
        }

        if (!(j2_val = (evhtp_json *)evhtp_kvmap_find(j2_map, key))) {
            return -1;
        }

        if (j_compare_(j1_val, j2_val, cb) == -1) {
            return -1;
        }

        temp = evhtp_kvmap_next(ent);
    }

    return 0;
} /* j_object_compare_ */

static int
j_string_compare_(evhtp_json * j1, evhtp_json * j2, evhtp_json_key_filtercb cb) {
    const char * j1_str;
    const char * j2_str;

    if (!(j1_str = evhtp_json_get_string(j1))) {
        return -1;
    }

    if (!(j2_str = evhtp_json_get_string(j2))) {
        return -1;
    }

    if (strcmp(j1_str, j2_str)) {
        return -1;
    }

    return 0;
}

static int
j_boolean_compare_(evhtp_json * j1, evhtp_json * j2, evhtp_json_key_filtercb cb) {
    if (!j1 || !j2) {
        return -1;
    }

    if (j_type_(j1) != evhtp_json_vtype_bool) {
        return -1;
    }

    if (j_type_(j2) != evhtp_json_vtype_bool) {
        return -1;
    }

    if (evhtp_json_get_boolean(j1) != evhtp_json_get_boolean(j2)) {
        return -1;
    }

    return 0;
}

static int
j_null_compare_(evhtp_json            * j1,
                evhtp_json            * j2,
                evhtp_json_key_filtercb cb) {
    if (j1 == NULL || j2 == NULL) {
        return -1;
    }

    if (j_type_(j1) != evhtp_json_vtype_null
        || j_type_(j2) != evhtp_json_vtype_null) {
        return -1;
    }

    return 0;
}

static int
j_compare_(evhtp_json * j1, evhtp_json * j2, evhtp_json_key_filtercb cb) {
    if (j1 == NULL || j2 == NULL) {
        return -1;
    }

    if (j_type_(j1) != j_type_(j2)) {
        return -1;
    }

    if (evhtp_json_get_size(j1) != evhtp_json_get_size(j2)) {
        return -1;
    }

    switch (j_type_(j1)) {
        case evhtp_json_vtype_number:
            return j_number_compare_(j1, j2, cb);
        case evhtp_json_vtype_array:
            return j_array_compare_(j1, j2, cb);
        case evhtp_json_vtype_object:
            return j_object_compare_(j1, j2, cb);
        case evhtp_json_vtype_string:
            return j_string_compare_(j1, j2, cb);
        case evhtp_json_vtype_bool:
            return j_boolean_compare_(j1, j2, cb);
        case evhtp_json_vtype_null:
            return j_null_compare_(j2, j2, cb);
        default:
            return -1;
    }

    return 0;
}

int
evhtp_json_compare(evhtp_json            * j1,
                   evhtp_json            * j2,
                   evhtp_json_key_filtercb cb) {
    return j_compare_(j1, j2, cb);
}

