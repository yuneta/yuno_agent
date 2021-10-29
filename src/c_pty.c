/***********************************************************************
 *          C_PTY.C
 *          Pty GClass.
 *
 *          Pseudoterminal uv-mixin.
 *
 *          Code inspired in the project: https://github.com/tsl0922/ttyd
 *          Copyright (c) 2016 Shuanglei Tao <tsl0922@gmail.com>
 *
 *          Copyright (c) 2021 Niyamaka.
 *          All Rights Reserved.
 ***********************************************************************/
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pty.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include "c_pty.h"

/***************************************************************************
 *              Constants
 ***************************************************************************/

/***************************************************************************
 *              Structures
 ***************************************************************************/

/***************************************************************************
 *              Prototypes
 ***************************************************************************/
PRIVATE void catcher(int signum);
PRIVATE void on_close_cb(uv_handle_t* handle);
PRIVATE BOOL fd_set_cloexec(const int fd);
PRIVATE BOOL fd_duplicate(int fd, uv_pipe_t *pipe);
PRIVATE void on_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
PRIVATE void on_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
PRIVATE int write_data_to_pty(hgobj gobj, GBUFFER *gbuf);


/***************************************************************************
 *          Data: config, public data, private data
 ***************************************************************************/

/*---------------------------------------------*
 *      Attributes - order affect to oid's
 *---------------------------------------------*/
PRIVATE sdata_desc_t tattr_desc[] = {
/*-ATTR-type------------name--------------------flag--------default-description---------- */
SDATA (ASN_OCTET_STR,   "process",              SDF_RD,     "bash", "Process to execute in pseudo terminal"),
SDATA (ASN_UNSIGNED,    "rows",                 SDF_RD,     24,     "Rows"),
SDATA (ASN_UNSIGNED,    "cols",                 SDF_RD,     80,     "Columns"),
SDATA (ASN_OCTET_STR,   "cwd",                  SDF_RD,     "",     "Current work directory"),
SDATA (ASN_POINTER,     "user_data",            0,          0,      "user data"),
SDATA (ASN_POINTER,     "user_data2",           0,          0,      "more user data"),
SDATA (ASN_POINTER,     "subscriber",           0,          0,      "subscriber of output-events. If it's null then subscriber is the parent."),
SDATA_END()
};

/*---------------------------------------------*
 *      GClass trace levels
 *---------------------------------------------*/
enum {
    TRACE_TRAFFIC           = 0x0001,
};
PRIVATE const trace_level_t s_user_trace_level[16] = {
{"traffic",             "Trace dump traffic"},
{0, 0},
};


/*---------------------------------------------*
 *              Private data
 *---------------------------------------------*/
#define BFINPUT_SIZE (2*1024)

typedef struct _PRIVATE_DATA {
    int rows;
    int cols;
    char *argv[2]; // HACK Command or process (by the moment) without arguments

    char uv_read_active;
    char uv_req_write_active;
    uv_write_t uv_req_write;

    uv_pipe_t uv_in;   // Duplicated fd of pty, use for put data into terminal
    uv_pipe_t uv_out;  // Duplicated fd of pty, use for get the output of the terminal
    char uv_handler_in_active;
    char uv_handler_out_active;

    pid_t pty;      // file descriptor of pseudoterminal
    int pid;        // child pid

    char slave_name[NAME_MAX+1];
    char bfinput[BFINPUT_SIZE];
} PRIVATE_DATA;




            /******************************
             *      Framework Methods
             ******************************/




/***************************************************************************
 *      Framework Method create
 ***************************************************************************/
PRIVATE void mt_create(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    const char *process = gobj_read_str_attr(gobj, "process");
    priv->argv[0] = (char *)gbmem_strdup(process);
    priv->argv[1] = 0;

    priv->pty = -1;

    /*
     *  Do copy of heavy used parameters, for quick access.
     *  HACK The writable attributes must be repeated in mt_writing method.
     */
    SET_PRIV(rows,      gobj_read_uint32_attr)
    SET_PRIV(cols,      gobj_read_uint32_attr)

    hgobj subscriber = (hgobj)gobj_read_pointer_attr(gobj, "subscriber");
    if(!subscriber)
        subscriber = gobj_parent(gobj);
    gobj_subscribe_event(gobj, NULL, NULL, subscriber);

}

/***************************************************************************
 *      Framework Method destroy
 ***************************************************************************/
PRIVATE void mt_destroy(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    GBMEM_FREE(priv->argv[0]);
}

/***************************************************************************
 *      Framework Method writing
 ***************************************************************************/
PRIVATE void mt_writing(hgobj gobj, const char *path)
{
//     PRIVATE_DATA *priv = gobj_priv_data(gobj);
//
//     IF_EQ_SET_PRIV(sockname,                      gobj_read_str_attr)
//     END_EQ_SET_PRIV()
}

/***************************************************************************
 *      Framework Method start
 ***************************************************************************/
PRIVATE int mt_start(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    int master, pid;

    if(priv->pty != -1) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "pty terminal ALREADY open",
            NULL
        );
        return -1;
    }

    uv_disable_stdio_inheritance();

    BOOL tty_empty = (empty_string(priv->argv[0]))?TRUE:FALSE;

    struct winsize size = {
        priv->rows,
        priv->cols,
        0,
        0
    };
    pid = forkpty(&master, priv->slave_name, NULL, &size);
    if (pid < 0) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_SYSTEM_ERROR,
            "msg",          "%s", "forkpty() FAILED",
            "errno",        "%d", errno,
            "strerror",     "%s", strerror(errno),
            NULL
        );
        return -1;

    } else if (pid == 0) {
        // Child
        setsid();
        const char *cwd = gobj_read_str_attr(gobj, "cwd");
        if(!empty_string(cwd)) {
            chdir(cwd);
        }

        if(!tty_empty) {
            int ret = execvp(priv->argv[0], priv->argv);
            if(ret < 0) {
                log_error(0,
                    "gobj",         "%s", gobj_full_name(gobj),
                    "function",     "%s", __FUNCTION__,
                    "msgset",       "%s", MSGSET_SYSTEM_ERROR,
                    "msg",          "%s", "forkpty() FAILED",
                    "errno",        "%d", errno,
                    "strerror",     "%s", strerror(errno),
                    NULL
                );
            }
            exit(0); // Child will die after exit of execute command
        } else {
            struct sigaction sact;
            sigemptyset(&sact.sa_mask);
            sact.sa_flags = 0;
            sact.sa_handler = catcher;

            if(sigaction(SIGUSR1, &sact, NULL) < 0) {
                log_error(0,
                    "gobj",         "%s", gobj_full_name(gobj),
                    "function",     "%s", __FUNCTION__,
                    "msgset",       "%s", MSGSET_SYSTEM_ERROR,
                    "msg",          "%s", "sigaction() FAILED",
                    "errno",        "%d", errno,
                    "strerror",     "%s", strerror(errno),
                    NULL
                );
            }

            sigset_t sigset;
            sigfillset(&sigset);
            sigdelset(&sigset, SIGUSR1);
            if(sigsuspend(&sigset) < 0) {
                log_error(0,
                    "gobj",         "%s", gobj_full_name(gobj),
                    "function",     "%s", __FUNCTION__,
                    "msgset",       "%s", MSGSET_SYSTEM_ERROR,
                    "msg",          "%s", "sigsuspend() FAILED",
                    "errno",        "%d", errno,
                    "strerror",     "%s", strerror(errno),
                    NULL
                );
            }
            trace_msg("🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋 exit pty");
            exit(0); // Child will die after receive signal
        }
    }

    int flags = fcntl(master, F_GETFL);
    if (flags == -1) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_SYSTEM_ERROR,
            "msg",          "%s", "fcntl(F_GETFL) FAILED",
            "errno",        "%d", errno,
            "strerror",     "%s", strerror(errno),
            NULL
        );
        close(master);
        uv_kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return -1;
    }

    if(fcntl(master, F_SETFD, flags | O_NONBLOCK) == -1) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_SYSTEM_ERROR,
            "msg",          "%s", "fcntl(F_SETFD) FAILED",
            "errno",        "%d", errno,
            "strerror",     "%s", strerror(errno),
            NULL
        );
        close(master);
        uv_kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return -1;
    }
    if(!fd_set_cloexec(master)) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_SYSTEM_ERROR,
            "msg",          "%s", "fd_set_cloexec() FAILED",
            "errno",        "%d", errno,
            "strerror",     "%s", strerror(errno),
            NULL
        );
        close(master);
        uv_kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return -1;
    }

    if(1) {
        uv_pipe_init(yuno_uv_event_loop(), &priv->uv_in, 0);
        priv->uv_in.data = gobj;

        if(gobj_trace_level(gobj) & TRACE_UV) {
            trace_msg(">>> uv_pipe_init pty in p=%p", &priv->uv_in);
        }

        if(!fd_duplicate(master, &priv->uv_in)) {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_SYSTEM_ERROR,
                "msg",          "%s", "fd_duplicate() FAILED",
                "errno",        "%d", errno,
                "strerror",     "%s", strerror(errno),
                NULL
            );
            close(master);
            uv_kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            return -1;
        }
        priv->uv_handler_in_active = TRUE;
    }

    if(!tty_empty) {
        uv_pipe_init(yuno_uv_event_loop(), &priv->uv_out, 0);
        priv->uv_out.data = gobj;

        if(gobj_trace_level(gobj) & TRACE_UV) {
            trace_msg(">>> uv_pipe_init pty out p=%p", &priv->uv_out);
        }

        if(!fd_duplicate(master, &priv->uv_out)) {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_SYSTEM_ERROR,
                "msg",          "%s", "fd_duplicate() FAILED",
                "errno",        "%d", errno,
                "strerror",     "%s", strerror(errno),
                NULL
            );
            close(master);
            uv_kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            return -1;
        }
        priv->uv_handler_out_active = TRUE;
    }

    priv->pty = master;     // file descriptor of pseudoterminal
    priv->pid = pid;        // child pid

    if(priv->uv_handler_out_active) {
        if(gobj_trace_level(gobj) & TRACE_UV) {
            trace_msg(">>> uv_read_start pty out p=%p", &priv->uv_out);
        }
        priv->uv_read_active = 1;
        uv_read_start((uv_stream_t*)&priv->uv_out, on_alloc_cb, on_read_cb);
    }

    json_t *kw_on_open = json_pack("{s:s, s:s, s:s, s:i, s:i}",
        "name", gobj_name(gobj),
        "process", priv->argv[0],
        "slave_name", priv->slave_name,
        "rows", (int)priv->rows,
        "cols", (int)priv->cols
    );
    gobj_publish_event(gobj, "EV_TTY_OPEN", kw_on_open);

    return 0;
}

/***************************************************************************
 *      Framework Method stop
 ***************************************************************************/
PRIVATE int mt_stop(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(priv->uv_read_active) {
        uv_read_stop((uv_stream_t *)&priv->uv_out);
        priv->uv_read_active = 0;
    }

    if(priv->uv_handler_in_active) {
        if(gobj_trace_level(gobj) & TRACE_UV) {
            trace_msg(">>> uv_close(cb %d) pty in p=%p",
                !gobj_is_imminent_destroy(gobj),
                &priv->uv_in
            );
        }
        uv_close((uv_handle_t *)&priv->uv_in,
            gobj_is_imminent_destroy(gobj)?0:on_close_cb
        );
    }
    if(priv->uv_handler_out_active) {
        if(gobj_trace_level(gobj) & TRACE_UV) {
            trace_msg(">>> uv_close(cb %d) pty out p=%p",
                !gobj_is_imminent_destroy(gobj),
                &priv->uv_out
            );
        }
        uv_close((uv_handle_t *)&priv->uv_out,
            gobj_is_imminent_destroy(gobj)?0:on_close_cb
        );
    }

    if(priv->pty != -1) {
        close(priv->pty);
        priv->pty = -1;
    }

    if(priv->pid > 0) {
trace_msg("🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋 1111");
        if(uv_kill(priv->pid, 0) == 0) {
trace_msg("🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋 2222");
            uv_kill(priv->pid, SIGUSR1); //SIGUSR1); //  SIGKILL); // TODO
            waitpid(priv->pid, NULL, 0);
trace_msg("🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋 3333");
        }
        priv->pid = -1;
    }

    return 0;
}




            /***************************
             *      Local Methods
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE void catcher(int signum)
{
printf("🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋 %d\n", signum);
printf("🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋 %d\n", signum);
printf("🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋 %d\n", signum);
    switch (signum) {
        case SIGUSR1:
            //exit(0);
printf("🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋🙋 SIGUSR1 %d\n", signum);
            break;
        default:
            break;
    }
}

/***************************************************************************
 *  Only NOW you can destroy this gobj,
 *  when uv has released the handler.
 ***************************************************************************/
PRIVATE void on_close_cb(uv_handle_t* handle)
{
    hgobj gobj = handle->data;
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if((uv_handle_t *)handle == (uv_handle_t *)&priv->uv_in) {
        if(gobj_trace_level(gobj) & TRACE_UV) {
            trace_msg("<<< on_close_cb pty in p=%p", &priv->uv_in);
        }
        priv->uv_handler_in_active = 0;

    } else if((uv_handle_t *)handle == (uv_handle_t *)&priv->uv_out) {
        if(gobj_trace_level(gobj) & TRACE_UV) {
            trace_msg("<<< on_close_cb pty out p=%p", &priv->uv_out);
        }
        priv->uv_handler_out_active = 0;

    } else {
        log_error(0,
            "gobj",         "%s", __FILE__,
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_LIBUV_ERROR,
            "msg",          "%s", "handler UNKNOWN",
            "pty",          "%p", handle,
            NULL
        );
        return;
    }

    if(!priv->uv_handler_in_active && !priv->uv_handler_out_active) {
        json_t *kw_on_close = json_pack("{s:s, s:s, s:s}",
            "name", gobj_name(gobj),
            "process", priv->argv[0],
            "slave_name", priv->slave_name
        );
        gobj_publish_event(gobj, "EV_TTY_CLOSE", kw_on_close);

        if(gobj_is_volatil(gobj)) {
            gobj_destroy(gobj);
        } else {
            gobj_publish_event(gobj, "EV_STOPPED", 0);
        }
    }
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE BOOL fd_set_cloexec(const int fd)
{
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0) {
        return FALSE;
    }
    return (flags & FD_CLOEXEC) == 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != -1;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE BOOL fd_duplicate(int fd, uv_pipe_t *pipe)
{
    int fd_dup = dup(fd);
    if (fd_dup < 0) {
        return FALSE;
    }

    if (!fd_set_cloexec(fd_dup)) {
        return FALSE;
    }

    int status = uv_pipe_open(pipe, fd_dup);
    if (status) {
        close(fd_dup);
    }
    return status == 0;
}

/***************************************************************************
 *  on alloc callback
 ***************************************************************************/
PRIVATE void on_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    hgobj gobj = handle->data;
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    // TODO: OPTIMIZE to use few memory
    buf->base = priv->bfinput;
    buf->len = sizeof(priv->bfinput);
}

/***************************************************************************
 *  on read callback
 ***************************************************************************/
PRIVATE void on_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    hgobj gobj = stream->data;
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(gobj_trace_level(gobj) & TRACE_UV) {
        trace_msg("<<< on_read_cb %d pty out p=%p",
            nread,
            &priv->uv_out
        );
    }

    if(nread < 0) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_LIBUV_ERROR,
            "msg",          "%s", "read FAILED",
            "error",        "%d", nread,
            "uv_error",     "%s", uv_err_name(nread),
            NULL
        );
        if(gobj_is_running(gobj)) {
            gobj_stop(gobj); // auto-stop
        }
        return;
    }

    if(nread == 0) {
        // Yes, sometimes arrive with nread 0.
        return;
    }

    if(gobj_trace_level(gobj) & TRACE_TRAFFIC) {
        log_debug_dump(
            0,
            buf->base,
            nread,
            "READ from PTY %s",
            gobj_short_name(gobj)
        );
    }

    GBUFFER *gbuf = gbuf_string2base64(buf->base, nread);
    if(!gbuf) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_MEMORY_ERROR,
            "msg",          "%s", "Pty encode to base64 faild",
            NULL
        );
        return;
    }

    json_t *kw = json_pack("{s:s, s:s, s:s, s:s}",
        "name", gobj_name(gobj),
        "process", priv->argv[0],
        "slave_name", priv->slave_name,
        "content64", gbuf_cur_rd_pointer(gbuf)
    );
    gobj_publish_event(gobj, "EV_TTY_DATA", kw);
    gbuf_decref(gbuf);
}

/***************************************************************************
 *  on write callback
 ***************************************************************************/
PRIVATE void on_write_cb(uv_write_t* req, int status)
{
    hgobj gobj = req->data;
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    priv->uv_req_write_active = 0;

    if(gobj_trace_level(gobj) & TRACE_UV) {
        trace_msg(">>> on_write_cb pty in p=%p",
            &priv->uv_in
        );
    }

    if(status != 0) {
        if(gobj_is_running(gobj)) {
            gobj_stop(gobj); // auto-stop
        }
        return;
    }
}

/***************************************************************************
 *  Write data to pseudo terminal
 ***************************************************************************/
PRIVATE int write_data_to_pty(hgobj gobj, GBUFFER *gbuf)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(priv->uv_req_write_active) {
        log_error(LOG_OPT_TRACE_STACK,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_OPERATIONAL_ERROR,
            "msg",          "%s", "uv_req_write ALREADY ACTIVE",
            NULL
        );
        gbuf_decref(gbuf);
        return -1;
    }

    priv->uv_req_write_active = 1;
    priv->uv_req_write.data = gobj;

    size_t ln = gbuf_chunk(gbuf); // TODO y si ln es 0??????????

    char *bf = gbuf_get(gbuf, ln);
    uv_buf_t b[] = {
        { .base = bf, .len = ln}
    };
    uint32_t trace = gobj_trace_level(gobj);
    if((trace & TRACE_UV)) {
        trace_msg(">>> uv_write pty in p=%p, send %d\n", (uv_stream_t *)&priv->uv_in, ln);
    }
    int ret = uv_write(
        &priv->uv_req_write,
        (uv_stream_t*)&priv->uv_in,
        b,
        1,
        on_write_cb
    );
    if(ret < 0) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_LIBUV_ERROR,
            "msg",          "%s", "uv_write FAILED",
            "uv_error",     "%s", uv_err_name(ret),
            "ln",           "%d", ln,
            NULL
        );
        if(gobj_is_running(gobj)) {
            gobj_stop(gobj); // auto-stop
        }
        return -1;
    }
    if((trace & TRACE_TRAFFIC)) {
        log_debug_dump(
            0,
            bf,
            ln,
            "WRITE to PTY %s",
            gobj_short_name(gobj)
        );
    }

    return 0;
}




            /***************************
             *      Actions
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_write_tty(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    const char *content64 = kw_get_str(kw, "content64", 0, 0);
    if(empty_string(content64)) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "content64 empty",
            NULL
        );
        JSON_DECREF(kw);
        return -1;
    }

    GBUFFER *gbuf = gbuf_decodebase64string(content64);

    write_data_to_pty(gobj, gbuf);
    gbuf_decref(gbuf);

    JSON_DECREF(kw);
    return 0;
}

/***************************************************************************
 *                          FSM
 ***************************************************************************/
PRIVATE const EVENT input_events[] = {
    // top input
    {"EV_WRITE_TTY",    0,  0,  ""},
    // bottom input
    // internal
    {NULL, 0, 0, ""}
};
PRIVATE const EVENT output_events[] = {
    {"EV_TTY_DATA",     0,  0,  ""},
    {"EV_TTY_OPEN",     0,  0,  ""},
    {"EV_TTY_CLOSE",    0,  0,  ""},
    {NULL, 0, 0, ""}
};
PRIVATE const char *state_names[] = {
    "ST_IDLE",          /* H2UV handler for UV */
    NULL
};

PRIVATE EV_ACTION ST_IDLE[] = {
    {"EV_WRITE_TTY",    ac_write_tty,   0},
    {0,0,0}
};

PRIVATE EV_ACTION *states[] = {
    ST_IDLE,
    NULL
};


PRIVATE FSM fsm = {
    input_events,
    output_events,
    state_names,
    states,
};

/***************************************************************************
 *              GClass
 ***************************************************************************/
/*---------------------------------------------*
 *              Local methods table
 *---------------------------------------------*/
PRIVATE LMETHOD lmt[] = {
    {0, 0, 0}
};

/*---------------------------------------------*
 *              GClass
 *---------------------------------------------*/
PRIVATE GCLASS _gclass = {
    0,  // base
    GCLASS_PTY_NAME,
    &fsm,
    {
        mt_create,
        0, //mt_create2,
        mt_destroy,
        mt_start,
        mt_stop,
        0, //mt_play,
        0, //mt_pause,
        mt_writing,
        0, //mt_reading,
        0, //mt_subscription_added,
        0, //mt_subscription_deleted,
        0, //mt_child_added,
        0, //mt_child_removed,
        0, //mt_stats,
        0, //mt_command_parser,
        0, //mt_inject_event,
        0, //mt_create_resource,
        0, //mt_list_resource,
        0, //mt_update_resource,
        0, //mt_delete_resource,
        0, //mt_add_child_resource_link
        0, //mt_delete_child_resource_link
        0, //mt_get_resource
        0, //mt_authorization_parser,
        0, //mt_authenticate,
        0, //mt_list_childs,
        0, //mt_stats_updated,
        0, //mt_disable,
        0, //mt_enable,
        0, //mt_trace_on,
        0, //mt_trace_off,
        0, //mt_gobj_created,
        0, //mt_future33,
        0, //mt_future34,
        0, //mt_publish_event,
        0, //mt_publication_pre_filter,
        0, //mt_publication_filter,
        0, //mt_authz_checker,
        0, //mt_future39,
        0, //mt_create_node,
        0, //mt_update_node,
        0, //mt_delete_node,
        0, //mt_link_nodes,
        0, //mt_future44,
        0, //mt_unlink_nodes,
        0, //mt_topic_jtree,
        0, //mt_get_node,
        0, //mt_list_nodes,
        0, //mt_shoot_snap,
        0, //mt_activate_snap,
        0, //mt_list_snaps,
        0, //mt_treedbs,
        0, //mt_treedb_topics,
        0, //mt_topic_desc,
        0, //mt_topic_links,
        0, //mt_topic_hooks,
        0, //mt_node_parents,
        0, //mt_node_childs,
        0, //mt_list_instances,
        0, //mt_node_tree,
        0, //mt_topic_size,
        0, //mt_future62,
        0, //mt_future63,
        0, //mt_future64
    },
    lmt,
    tattr_desc,
    sizeof(PRIVATE_DATA),
    0,  // acl
    s_user_trace_level,
    0,  // cmds
    0,  // gcflag
};

/***************************************************************************
 *              Public access
 ***************************************************************************/
PUBLIC GCLASS *gclass_pty(void)
{
    return &_gclass;
}
