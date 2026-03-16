#include "vex.h"
#include <signal.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static Job job_table[MAX_JOBS];
static int next_job_id = 1;
static pid_t shell_pgid;

volatile sig_atomic_t vex_got_sigwinch = 0;

static void sigchld_handler(int sig) {
    (void)sig;

}

static void sigwinch_handler(int sig) {
    (void)sig;
    vex_got_sigwinch = 1;
}

void job_init(void) {

    shell_pgid = getpid();
    if (isatty(STDIN_FILENO)) {
        setpgid(shell_pgid, shell_pgid);
        tcsetpgrp(STDIN_FILENO, shell_pgid);
    }

    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGINT, SIG_IGN);

    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    sa.sa_handler = sigwinch_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGWINCH, &sa, NULL);

    memset(job_table, 0, sizeof(job_table));
}

pid_t job_shell_pgid(void) {
    return shell_pgid;
}

int job_add(pid_t pid, pid_t pgid, const char *cmd, bool background) {
    for (int i = 0; i < MAX_JOBS; i++) {
        if (job_table[i].pid == 0) {
            job_table[i] = (Job){
                .id = next_job_id++,
                .pid = pid,
                .pgid = pgid,
                .status = JOB_RUNNING,
                .exit_code = -1,
                .background = background,
                .notified = false,
                .cmd = strdup(cmd),
            };
            return job_table[i].id;
        }
    }
    return -1;
}

Job *job_get(int id) {
    for (int i = 0; i < MAX_JOBS; i++) {
        if (job_table[i].pid != 0 && job_table[i].id == id)
            return &job_table[i];
    }
    return NULL;
}

Job *job_by_pid(pid_t pid) {
    for (int i = 0; i < MAX_JOBS; i++) {
        if (job_table[i].pid == pid)
            return &job_table[i];
    }
    return NULL;
}

void job_remove(int id) {
    for (int i = 0; i < MAX_JOBS; i++) {
        if (job_table[i].id == id) {
            free(job_table[i].cmd);
            memset(&job_table[i], 0, sizeof(Job));
            return;
        }
    }
}

void job_reap(void) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        Job *j = job_by_pid(pid);
        if (!j) continue;

        if (WIFEXITED(status)) {
            j->status = JOB_DONE;
            j->exit_code = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            j->status = JOB_DONE;
            j->exit_code = 128 + WTERMSIG(status);
        } else if (WIFSTOPPED(status)) {
            j->status = JOB_STOPPED;
        }
    }
}

void job_print_all(FILE *out) {
    job_reap();
    bool any = false;
    for (int i = 0; i < MAX_JOBS; i++) {
        if (job_table[i].pid == 0) continue;
        any = true;
        const char *status_str = "Unknown";
        switch (job_table[i].status) {
        case JOB_RUNNING: status_str = "Running"; break;
        case JOB_STOPPED: status_str = "Stopped"; break;
        case JOB_DONE:    status_str = "Done";    break;
        }
        fprintf(out, "[%d]  %s\t\t%s\n",
                job_table[i].id, status_str, job_table[i].cmd);
    }
    if (!any) {
        fprintf(out, "No active jobs.\n");
    }
}

void job_notify(void) {
    job_reap();
    for (int i = 0; i < MAX_JOBS; i++) {
        if (job_table[i].pid == 0) continue;
        if (job_table[i].background && job_table[i].status == JOB_DONE &&
            !job_table[i].notified) {
            fprintf(stderr, "[%d]  Done\t\t%s\n",
                    job_table[i].id, job_table[i].cmd);
            job_table[i].notified = true;
        }
    }

    for (int i = 0; i < MAX_JOBS; i++) {
        if (job_table[i].pid != 0 && job_table[i].notified) {
            free(job_table[i].cmd);
            memset(&job_table[i], 0, sizeof(Job));
        }
    }
}

int job_wait(int id) {
    Job *j = job_get(id);
    if (!j) return -1;

    int status;
    while (j->status == JOB_RUNNING) {
        pid_t p = waitpid(j->pid, &status, WUNTRACED);
        if (p < 0) break;

        if (WIFEXITED(status)) {
            j->status = JOB_DONE;
            j->exit_code = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            j->status = JOB_DONE;
            j->exit_code = 128 + WTERMSIG(status);
        } else if (WIFSTOPPED(status)) {
            j->status = JOB_STOPPED;
            return 0;
        }
    }

    int code = j->exit_code;
    job_remove(id);
    return code;
}

int job_foreground(int id) {
    Job *j = job_get(id);
    if (!j) {
        vex_err("fg: no such job: %%%d", id);
        return -1;
    }

    fprintf(stderr, "%s\n", j->cmd);

    if (isatty(STDIN_FILENO)) {
        tcsetpgrp(STDIN_FILENO, j->pgid);
    }

    if (j->status == JOB_STOPPED) {
        kill(-j->pgid, SIGCONT);
        j->status = JOB_RUNNING;
    }

    j->background = false;

    int status;
    pid_t p = waitpid(j->pid, &status, WUNTRACED);

    if (isatty(STDIN_FILENO)) {
        tcsetpgrp(STDIN_FILENO, shell_pgid);
    }

    if (p < 0) {
        job_remove(id);
        return -1;
    }

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        job_remove(id);
        return code;
    }
    if (WIFSIGNALED(status)) {
        int code = 128 + WTERMSIG(status);
        job_remove(id);
        return code;
    }
    if (WIFSTOPPED(status)) {
        j->status = JOB_STOPPED;
        j->background = true;
        fprintf(stderr, "\n[%d]  Stopped\t\t%s\n", j->id, j->cmd);
        return 0;
    }

    job_remove(id);
    return -1;
}

int job_background(int id) {
    Job *j = job_get(id);
    if (!j) {
        vex_err("bg: no such job: %%%d", id);
        return -1;
    }

    if (j->status == JOB_STOPPED) {
        kill(-j->pgid, SIGCONT);
        j->status = JOB_RUNNING;
    }

    j->background = true;
    fprintf(stderr, "[%d]  %s &\n", j->id, j->cmd);
    return 0;
}

int job_kill(int id, int sig) {
    Job *j = job_get(id);
    if (!j) {
        vex_err("kill: no such job: %%%d", id);
        return -1;
    }

    if (kill(-j->pgid, sig) < 0) {
        vex_err("kill: %s", strerror(errno));
        return -1;
    }
    return 0;
}

void job_disown(int id) {
    Job *j = job_get(id);
    if (!j) {
        vex_err("disown: no such job: %%%d", id);
        return;
    }

    fprintf(stderr, "[%d]  disowned\t\t%s\n", j->id, j->cmd);
    free(j->cmd);
    memset(j, 0, sizeof(Job));
}

int job_last_id(void) {
    int max_id = -1;
    for (int i = 0; i < MAX_JOBS; i++) {
        if (job_table[i].pid != 0 && job_table[i].id > max_id)
            max_id = job_table[i].id;
    }
    return max_id;
}

int job_active_count(void) {
    int count = 0;
    for (int i = 0; i < MAX_JOBS; i++) {
        if (job_table[i].pid != 0 &&
            (job_table[i].status == JOB_RUNNING || job_table[i].status == JOB_STOPPED))
            count++;
    }
    return count;
}

void job_cleanup(void) {

    for (int i = 0; i < MAX_JOBS; i++) {
        if (job_table[i].pid != 0 && job_table[i].status == JOB_RUNNING) {
            kill(-job_table[i].pgid, SIGHUP);
        }
        free(job_table[i].cmd);
    }
    memset(job_table, 0, sizeof(job_table));
}
