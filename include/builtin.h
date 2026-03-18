#ifndef VEX_BUILTIN_H
#define VEX_BUILTIN_H

typedef VexValue *(*BuiltinFn)(EvalCtx *ctx, VexValue *input,
                               VexValue **args, size_t argc);

typedef struct {
    const char *name;
    BuiltinFn fn;
    const char *usage;
    const char *description;
} BuiltinCmd;

void builtins_init(void);

const BuiltinCmd *builtin_lookup(const char *name);

bool builtin_exists(const char *name);

size_t builtin_count(void);
const char *builtin_name(size_t i);

VexValue *builtin_echo(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_cd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_exit(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_let(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_env(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_ls(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_where(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_first(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_last(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_get(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_sort_by(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_each(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_lines(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_which(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_type_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_pwd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_help(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_select(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_reject(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_length(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_reverse(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_flatten(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_uniq(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_enumerate(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_skip(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_reduce(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_to_text(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_join(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_split(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_trim(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_replace(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_contains(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_length(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_downcase(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_upcase(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_starts_with(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_ends_with(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_from_json(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_to_json(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_from_csv(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_to_csv(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_from_toml(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_to_toml(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_open(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_save(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_glob(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_math_sum(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_avg(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_min(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_max(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_abs(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_round(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_j(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_ji(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_filter(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_jobs(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_fg(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_bg(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_kill(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_wait_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_ps(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_set(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_export(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_source(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_alias(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

const char *alias_lookup(const char *name);

VexValue *builtin_abbr(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
const char *abbr_lookup(const char *name);

VexValue *builtin_pushd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_popd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_dirs(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_complete(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
int comp_spec_get_kind(const char *cmd);
bool comp_spec_try_help(const char *cmd);
void plugin_register_completion(const char *cmd, const char *const *words);
size_t comp_spec_get_words(const char *cmd, const char ***words_out);

VexValue *builtin_complete_fn(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *comp_callback_query(const char *cmd, const char *prefix);
void builtin_set_comp_ctx(EvalCtx *ctx);

char **scope_complete_vars(const char *prefix, size_t *count);

VexValue *builtin_read(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_time(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_hash(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_rehash(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_history(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
void builtin_set_editor(void *editor);

VexValue *builtin_seq(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_sleep(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_test(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_is_file(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_is_dir(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_file_exists(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_file_size(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_basename(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_dirname(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_mkdir(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_rm(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_cp(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_mv(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_trap(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
const char *trap_get_exit_handler(void);
const char *trap_lookup(int signum);
void trap_check_pending(EvalCtx *ctx);

VexValue *builtin_getopts(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_select_menu(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_bindkey(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_true(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_false_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_printf(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_exec(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_eval(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_date(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_random(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_to_table(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_columns(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_values(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_update(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_insert(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_any(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_all(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_find(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_into_int(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_into_float(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_into_string(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_str_substring(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_chunks(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_window(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_input(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_unset(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_unalias(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_default(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_describe(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_wrap(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_do(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_is_empty (EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_str_capitalize(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_index_of(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_pad_left(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_pad_right(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_touch(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_path_join(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_path_parse(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_path_expand(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_take_while(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_skip_while(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_rotate(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_transpose(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_encode(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_decode(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_inspect(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_tee_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_umask_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_cal(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_uname(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_str_reverse(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_repeat(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_chars(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_words(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_range(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_par_each(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_which_all(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_has(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_ansi(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_char_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_term_size(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_url_parse(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_split_at(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_each_while(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_match(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_fill(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_error_make(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_try_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_ln(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_readlink(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_chmod(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_head_text(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_tail_text(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_tac(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_with_env(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_retry(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_timeout_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_defer(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
void builtin_run_defers(EvalCtx *ctx);
VexValue *builtin_parallel(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_str_count(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_bytes(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_take_until(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_min_by(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_max_by(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_sum_by(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_frequencies(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_to_yaml(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_from_ini(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_to_ini(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_mktemp_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_realpath_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_str_camel_case(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_snake_case(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_kebab_case(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_to_md(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_flat_map(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_every(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_interleave(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_load_env(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_format_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_bench(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_open_url(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_input_confirm(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_whoami(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_hostname_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_du(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_regex_replace(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_histogram(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_into_bool(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_into_record(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_into_list(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_watch(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_config_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_version(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_to_nuon(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_from_tsv(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_to_tsv(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_command(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_wc(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_zip(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_group_by(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_merge(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_append(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_prepend(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_sort(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_compact(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_disown(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_sqrt(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_pow(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_log(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_ceil(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_floor(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_sin(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_cos(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_tan(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_http_get(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_http_post(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_truncate(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_uptime(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_http_put(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_http_delete(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_http_head(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_pi(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_e(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_date_format(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_date_humanize(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_uniq_by(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_rename(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_drop(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_encode_uri(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_decode_uri(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_math_median(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_stddev(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_product(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_from_yaml(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_detect_columns(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_env_keys(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_sys(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_input_list(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_title_case(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_distance(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_split_row(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_seq_date(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_math_mod(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_exp(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_ln(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_starts_with_any(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_ends_with_any(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_collect(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_zip_with(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_from_xml(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_to_xml(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_path_exists(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_path_type(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_generate(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_math_asin(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_acos(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_atan(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_atan2(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_center(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_remove(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_group_by_fn(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_scan(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_chunks_by(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_path_dirname(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_path_basename_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_path_ext(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_to_html(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_sleep_ms(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_is_admin(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_math_gcd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_lcm(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_clamp(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_wrap(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_similarity(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_pairwise(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_cartesian(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_from_ssv(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_to_text_table(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_path_stem(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_path_rel(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_count_by(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_repeat_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_bits_and(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_bits_or(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_bits_xor(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_bits_not(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_bits_shl(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_bits_shr(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_into_filesize(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_into_duration(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_format_duration(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_loop_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_cmp(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_sort_by_fn(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_index_of(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_flat(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_from_lines(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_to_lines(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_hash_md5(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_hash_sha256(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_hash_crc32(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_df_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_free_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_id_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_groups_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_date_add(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_date_diff(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_date_parse(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_date_to_epoch(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_sign(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_hypot(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_log2(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_log10(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_regex_find(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_regex_split(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_bytes_length(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_bytes_at(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_bytes_slice(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_scan(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_escape(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_unescape(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_headers(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_move_col(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_into_datetime(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_each_with_index(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_debug(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_profile(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_table_flip(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_cross_join(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_left_join(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_hex(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_from_hex(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_factorial(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_is_prime(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_fibonacci(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_env_get(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_env_set(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_gzip(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_gunzip(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_tar_list(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_path_is_absolute(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_path_normalize(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_path_with_ext(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_ljust(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_rjust(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_split_column(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_fill_null(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_variance(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_compact_record(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_to_base(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_from_base(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_builtins(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_vars(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_ulimit(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_ansi_strip(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_str_is_numeric(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_inner_join(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_from_jsonl(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_to_jsonl(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_url_build(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_tar_extract(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_tar_create(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_path_home(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_env_remove(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_command_type(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_pivot(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_merge_deep(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_from_nuon(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_split_words(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_deg_to_rad(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_rad_to_deg(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_into_binary(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_from_binary(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_lerp(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_math_map_range(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_record_to_list(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_record_keys(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_record_values(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_hook_add(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_hook_list(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
void hooks_run_preexec(EvalCtx *ctx, const char *cmd);
void hooks_run_precmd(EvalCtx *ctx);
void hooks_run_chpwd(EvalCtx *ctx);

VexValue *builtin_prompt_fn(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_rprompt_fn(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
char *prompt_fn_eval(EvalCtx *ctx);
char *rprompt_fn_eval(EvalCtx *ctx);

bool vex_opt_errexit(void);
bool vex_opt_xtrace(void);
bool vex_opt_nounset(void);
bool vex_opt_noclobber(void);

VexValue *builtin_assert(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_shift(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_argparse(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_ssh_exec(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_scp_get(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_scp_put(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
VexValue *builtin_ssh_shell(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_pkg(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
void pkg_autoload(EvalCtx *ctx);

VexValue *builtin_theme(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);

VexValue *builtin_def_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc);
bool script_cmd_exists(const char *name);
VexValue *script_cmd_get_closure(const char *name);
size_t script_cmd_count(void);
const char *script_cmd_name(size_t i);
const char *script_cmd_description(size_t i);

VexValue *source_sh_file(EvalCtx *ctx, const char *path);
bool vex_is_sh_script(const char *path);
int vex_run_sh_script(const char *path, int script_argc, char **script_argv);

#endif
