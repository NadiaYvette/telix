/* POSIX pipe() for Telix — creates a pipe via the pipe server. */
#include <telix/syscall.h>
#include <telix/ipc.h>
#include <telix/fd.h>

extern uint32_t __telix_pipe_port;

int pipe(int pipefd[2]) {
    if (__telix_pipe_port == 0xFFFFFFFF)
        return -1;

    uint32_t reply_port = telix_port_create();
    uint64_t d2 = (uint64_t)reply_port << 32;
    telix_send(__telix_pipe_port, PIPE_CREATE_TAG, 0, 0, d2, 0);

    struct telix_msg msg;
    if (!telix_recv_msg(reply_port, &msg) || msg.tag != PIPE_OK_TAG) {
        telix_port_destroy(reply_port);
        return -1;
    }
    telix_port_destroy(reply_port);

    uint32_t read_handle = (uint32_t)msg.data[0];
    uint32_t write_handle = (uint32_t)msg.data[1];

    pipefd[0] = telix_fd_alloc(__telix_pipe_port, read_handle, FD_TYPE_PIPE, 0);
    pipefd[1] = telix_fd_alloc(__telix_pipe_port, write_handle, FD_TYPE_PIPE, 0);

    if (pipefd[0] < 0 || pipefd[1] < 0) {
        /* Clean up on failure. */
        if (pipefd[0] >= 0) telix_fd_close(pipefd[0]);
        if (pipefd[1] >= 0) telix_fd_close(pipefd[1]);
        return -1;
    }
    return 0;
}
