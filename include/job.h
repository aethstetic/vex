#ifndef VEX_JOB_H
#define VEX_JOB_H

#include <sys/types.h>
#include <signal.h>

typedef enum {
    JOB_RUNNING,
    JOB_STOPPED,
    JOB_DONE,
} JobStatus;

/* A tracked child process (foreground or background). */
typedef struct {
    int id;
    pid_t pid;
    pid_t pgid;
    JobStatus status;
    int exit_code;
    bool background;
    bool notified;
    char *cmd;
} Job;

#define MAX_JOBS 64

void job_init(void);

int job_add(pid_t pid, pid_t pgid, const char *cmd, bool background);

Job *job_get(int id);
Job *job_by_pid(pid_t pid);

void job_remove(int id);

void job_reap(void);

void job_print_all(FILE *out);

void job_notify(void);

int job_wait(int id);

int job_foreground(int id);

int job_background(int id);

int job_kill(int id, int sig);

int job_last_id(void);

int job_active_count(void);

pid_t job_shell_pgid(void);

void job_disown(int id);

void job_cleanup(void);

extern volatile sig_atomic_t vex_got_sigwinch;

#endif
