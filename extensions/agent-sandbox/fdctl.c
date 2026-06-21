// fdctl.c — tiny N-API addon: set FD_CLOEXEC on a file descriptor.
//
// Called by the OMP extension immediately after wrapping the inherited
// policy UI fd in a Node net.Socket.  This closes the approval fd across
// future execve() calls while keeping the current process socket usable.
//
// Build: cc -shared -o fdctl.node fdctl.c -I<node>/include/node
#include <fcntl.h>
#include <node_api.h>
#include <unistd.h>

static napi_value SetCloseOnExec(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, NULL, NULL);

    if (argc < 1) {
        napi_throw_error(env, NULL, "fd required");
        return NULL;
    }

    int32_t fd;
    napi_get_value_int32(env, args[0], &fd);

    int flags = fcntl(fd, F_GETFD);
    if (flags < 0) {
        napi_throw_error(env, NULL, "fcntl F_GETFD failed");
        return NULL;
    }

    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
        napi_throw_error(env, NULL, "fcntl F_SETFD failed");
        return NULL;
    }

    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_value fn;
    napi_create_function(env, NULL, NAPI_AUTO_LENGTH, SetCloseOnExec, NULL, &fn);
    napi_set_named_property(env, exports, "setCloseOnExec", fn);
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
