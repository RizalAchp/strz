#define CB_IMPLEMENTATION
#include "cb.h"

#define VERSION "5.2"
#define CINCLUDE "/usr/X11R6/include"
#define CFLAGS "-std=c99", "-Wall", "-Os"
#define CDEFS "_XOPEN_SOURCE=600", "VERSION=\"" VERSION "\""
#define LDFLAGS "-L/usr/X11R6/lib", "-lm", "-lrt", "-lX11", "-lutil", "-lXft"

static cb_path_t PREFIX = {0};
cb_status_t      on_configure(cb_t* cb, cb_config_t* cfg) {
    (void)cfg;
    cb_status_t  result    = CB_OK;
    cb_target_t* st_target = cb_create_exec(cb, "st");
    result &= cb_target_add_includes(st_target, CINCLUDE, NULL);
    result &= cb_target_add_defines(st_target, CDEFS, NULL);
    result &= cb_target_add_flags(st_target, CFLAGS, NULL);
    result &= cb_target_add_ldflags(st_target, LDFLAGS, NULL);
    result &= cb_target_link_library(
        st_target, cb_create_target_pkgconf(cb, cb_sv("fontconfig")),
        cb_create_target_pkgconf(cb, cb_sv("freetype2")),
        cb_create_target_pkgconf(cb, cb_sv("harfbuzz")), NULL);

    result &=
        cb_target_add_sources(st_target, "./st.c", "./x.c", "./hb.c", NULL);
    return result;
}

static cb_status_t on_pre_install(cb_t* cb, cb_config_t* cfg) {
    (void)cb;
    return cb_config_set_install_prefix(cfg, PREFIX);
}

static cb_status_t on_post_install(cb_t* cb, cb_config_t* cfg) {
    (void)cb, (void)cfg;
    cb_status_t result = CB_OK;
    cb_cmd_t    cmd    = {0};
    cb_cmd_append(&cmd, "tic", "-sx", "./st.info");
    result &= cb_cmd_run_sync(cmd);
    cb_cmd_free(cmd);
    return result;
}

int main(int argc, char* argv[]) {
    CB_REBUILD_SELF(argc, argv, "./cb.h");
    int result = EXIT_SUCCESS;

    PREFIX   = cb_path("/usr/local");
    cb_t* cb = cb_init(argc, argv);
    // cb_add_on_post_install_callback()
    cb_add_on_pre_install_callback(cb, on_pre_install);
    cb_add_on_post_install_callback(cb, on_post_install);

    if (cb_run(cb) == CB_ERR) cb_return_defer(EXIT_FAILURE);

defer:
    if (cb) cb_deinit(cb);
    return result;
}
