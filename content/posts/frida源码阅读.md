---
title: "Frida源码阅读"
date: 2024-03-12T13:37:48+08:00
draft: true
author: "tcc0lin"
tags: ["源码分析"]
categories: ["frida生态"]
---

以14.2.18版本为例
### 一、frida-server做了什么
#### 1.1 进程注入
```js
// frida-core/src/linux/linux-host-session.vala

protected override async Future<IOStream> perform_attach_to (uint pid, Cancellable? cancellable, out Object? transport)
        throws Error, IOError {
    PipeTransport.set_temp_directory (tempdir.path);

    var t = new PipeTransport ();

    var stream_request = Pipe.open (t.local_address, cancellable);

    uint id;
    string entrypoint = "frida_agent_main";
    var linjector = injector as Linjector;
#if HAVE_EMBEDDED_ASSETS
    id = yield linjector.inject_library_resource (pid, agent, entrypoint, t.remote_address, cancellable);
#else
    id = yield linjector.inject_library_file (pid, Config.FRIDA_AGENT_PATH, entrypoint, t.remote_address, cancellable);
#endif
    injectee_by_pid[pid] = id;

    transport = t;

    return stream_request;
}
```
perform_attach_to这里引入linjector来处理注入，注意这里的entrypoint
```js
// frida-core/src/linux/linjector.vala

public async uint inject_library_resource (uint pid, AgentDescriptor agent, string entrypoint, string data,
        Cancellable? cancellable) throws Error, IOError {
    ensure_tempdir_prepared ();
    return yield inject_library_file_with_template (pid, agent.get_path_template (), entrypoint, data, cancellable);
}

public async uint inject_library_file (uint pid, string path, string entrypoint, string data, Cancellable? cancellable)
        throws Error, IOError {
    return yield inject_library_file_with_template (pid, PathTemplate (path), entrypoint, data, cancellable);
}

private async uint inject_library_file_with_template (uint pid, PathTemplate path_template, string entrypoint, string data,
        Cancellable? cancellable) throws Error, IOError {
    ensure_tempdir_prepared ();
    uint id = next_injectee_id++;
    yield helper.inject_library_file (pid, path_template, entrypoint, data, tempdir.path, id, cancellable);
    pid_by_id[id] = pid;
    return id;
}

public async void inject_library_file (uint pid, PathTemplate path_template, string entrypoint, string data,
        string temp_path, uint id, Cancellable? cancellable) throws Error, IOError {
    string path = path_template.expand (arch_name_from_pid (pid));

    _do_inject (pid, path, entrypoint, data, temp_path, id);

    yield establish_session (id, pid);
}
```
最终调用了_do_inject
```c
// frida-core/src/linux/frida-helper-backend-glue.c
_frida_linux_helper_backend_do_inject (FridaLinuxHelperBackend * self, guint pid, const gchar * path, const gchar * entrypoint, const gchar * data, const gchar * temp_path, guint id, GError ** error)
{
  FridaInjectInstance * instance;
  FridaInjectParams params;
  guint offset, page_size;
  FridaRegs saved_regs;
  gboolean exited;

  params.pid = pid;
  params.so_path = path;
  params.entrypoint_name = entrypoint;
  params.entrypoint_data = data;

  params.fifo_path = NULL;

  offset = 0;
  page_size = gum_query_page_size ();

  params.code.offset = offset;
  params.code.size = page_size;
  offset += params.code.size;

  params.data.offset = offset;
  params.data.size = page_size;
  offset += params.data.size;

  params.guard.offset = offset;
  params.guard.size = page_size;
  offset += params.guard.size;

  params.stack.offset = offset;
  params.stack.size = page_size * 2;
  offset += params.stack.size;

  params.remote_address = 0;
  params.remote_size = offset;

  params.open_impl = frida_resolve_libc_function (pid, "open");
  params.close_impl = frida_resolve_libc_function (pid, "close");
  params.write_impl = frida_resolve_libc_function (pid, "write");
  params.syscall_impl = frida_resolve_libc_function (pid, "syscall");
  if (params.open_impl == 0 || params.close_impl == 0 || params.write_impl == 0 || params.syscall_impl == 0)
    goto no_libc;

#if defined (HAVE_GLIBC)
  params.dlopen_impl = frida_resolve_libc_function (pid, "__libc_dlopen_mode");
  params.dlclose_impl = frida_resolve_libc_function (pid, "__libc_dlclose");
  params.dlsym_impl = frida_resolve_libc_function (pid, "__libc_dlsym");
#elif defined (HAVE_UCLIBC)
  params.dlopen_impl = frida_resolve_linker_address (params.pid, dlopen);
  params.dlclose_impl = frida_resolve_linker_address (params.pid, dlclose);
  params.dlsym_impl = frida_resolve_linker_address (params.pid, dlsym);
#elif defined (HAVE_ANDROID)
  params.dlopen_impl = frida_resolve_android_dlopen (pid);
  params.dlclose_impl = frida_resolve_linker_address (pid, dlclose);
  params.dlsym_impl = frida_resolve_linker_address (pid, dlsym);
#endif
  if (params.dlopen_impl == 0 || params.dlclose_impl == 0 || params.dlsym_impl == 0)
    goto no_libc;

  instance = frida_inject_instance_new (self, id, pid, temp_path);
  if (instance->executable_path == NULL)
    goto premature_termination;

  if (!frida_inject_instance_attach (instance, &saved_regs, error))
    goto premature_termination;

  params.fifo_path = instance->fifo_path;
  params.remote_address = frida_remote_alloc (pid, params.remote_size, PROT_READ | PROT_WRITE, error);
  if (params.remote_address == 0)
    goto premature_termination;
  instance->remote_payload = params.remote_address;
  instance->remote_size = params.remote_size;

  if (!frida_inject_instance_emit_and_transfer_payload (frida_inject_instance_emit_payload_code, &params, &instance->entrypoint, error))
    goto premature_termination;
  instance->stack_top = params.remote_address + params.stack.offset + params.stack.size;
  instance->trampoline_data = params.remote_address + params.data.offset;

  if (!frida_inject_instance_start_remote_thread (instance, &exited, error) && !exited)
    goto premature_termination;

  if (!exited)
    frida_inject_instance_detach (instance, &saved_regs, NULL);
  else
    g_clear_error (error);

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->inject_instances), GUINT_TO_POINTER (id), instance);

  return;

no_libc:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unable to inject library into process without libc");
    return;
  }
premature_termination:
  {
    frida_inject_instance_free (instance, FRIDA_UNLOAD_POLICY_IMMEDIATE);
    return;
  }
}
```
frida_inject_instance_attach函数中定义了真正的attach实现
```c
static gboolean
frida_inject_instance_attach (FridaInjectInstance * self, FridaRegs * saved_regs, GError ** error)
{
  const pid_t pid = self->pid;
  gboolean can_seize;
  long ret;
  int attach_errno;
  const gchar * failed_operation;
  gboolean maybe_already_attached, success;

  can_seize = frida_is_seize_supported ();

  if (can_seize)
    ret = ptrace (PTRACE_SEIZE, pid, NULL, PTRACE_O_TRACEEXEC);
  else
    ret = ptrace (PTRACE_ATTACH, pid, NULL, NULL);
  attach_errno = errno;

  maybe_already_attached = (ret != 0 && attach_errno == EPERM);
  if (maybe_already_attached)
  {
    ret = frida_get_regs (pid, saved_regs);
    CHECK_OS_RESULT (ret, ==, 0, "frida_get_regs");

    self->already_attached = TRUE;
  }
  else
  {
    CHECK_OS_RESULT (ret, ==, 0, can_seize ? "PTRACE_SEIZE" : "PTRACE_ATTACH");

    self->already_attached = FALSE;

    if (can_seize)
    {
      ret = ptrace (PTRACE_INTERRUPT, pid, NULL, NULL);
      CHECK_OS_RESULT (ret, ==, 0, "PTRACE_INTERRUPT");
    }

    success = frida_wait_for_attach_signal (pid);
    if (!success)
      goto wait_failed;

    ret = frida_get_regs (pid, saved_regs);
    if (ret != 0)
      goto wait_failed;
  }

  return TRUE;

os_failure:
  {
    if (attach_errno == EPERM)
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_PERMISSION_DENIED,
          "Unable to access process with pid %u due to system restrictions;"
          " try `sudo sysctl kernel.yama.ptrace_scope=0`, or run Frida as root",
          pid);
    }
    else
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_NOT_SUPPORTED,
          "Unexpected error while attaching to process with pid %u (%s returned '%s')",
          pid, failed_operation, g_strerror (errno));
    }

    return FALSE;
  }
wait_failed:
  {
    ptrace (PTRACE_DETACH, pid, NULL, NULL);

    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while attaching to process with pid %u",
        pid);

    return FALSE;
  }
}
```
可以看到，frida注入的选型是使用到了ptrace来实现，在注入使用可以看到调用了frida_remote_alloc来申请内存空间将agent copy到目标进程中执行代码，执行完成之后调用detach
#### 1.2 frida-agent启动
在perform_attach_to函数中完成动态注入后执行的函数符号是frida_agent_main，对应的文件是
```js
// frida-core/lib/agent/agent.vala
namespace Frida.Agent {
	public void main (string agent_parameters, ref Frida.UnloadPolicy unload_policy, void * injector_state) {
		if (Runner.shared_instance == null)
			Runner.create_and_run (agent_parameters, ref unload_policy, injector_state);
		else
			Runner.resume_after_fork (ref unload_policy, injector_state);
	}

	private enum StopReason {
		UNLOAD,
		FORK
	}
    ......
}
```
调用链路如下
```
Runner.create_and_run->shared_instance.run->Runner.run->Runner.start
```
其中Runner.run函数在调用完start后会进入main_loop循环，直至进程退出或者收到server的解除命令
Runner.start的作用是准备Interceptor以及GumJS的ScriptBackend，并连接到启动时指定的transport_uri建立通信隧道
### 二、frida-gadget做了什么
gadget本身是一个动态库，在加载到目标进程中后会马上触发ctor执行指定代码，默认情况下是挂起当前进程并监听在27042端口等待Host的连接并恢复运行。其文件路径为lib/gadget/gadget.vala，启动入口为
```js
// frida-core/lib/gadget/gadget.vala

public void load (Gum.MemoryRange? mapped_range, string? config_data, int * result) {
    if (loaded)
        return;
    loaded = true;

    Environment.init ();

    Gee.Promise<int>? request = null;
    if (result != null)
        request = new Gee.Promise<int> ();

    location = detect_location (mapped_range);

    try {
        config = (config_data != null)
            ? parse_config (config_data)
            : load_config (location);
    } catch (Error e) {
        log_warning (e.message);
        return;
    }

    Gum.Process.set_code_signing_policy (config.code_signing);

    Gum.Cloak.add_range (location.range);

    exceptor = Gum.Exceptor.obtain ();

    wait_for_resume_needed = true;

    var listen_interaction = config.interaction as ListenInteraction;
    if (listen_interaction != null && listen_interaction.on_load == ListenInteraction.LoadBehavior.RESUME) {
        wait_for_resume_needed = false;
    }

    if (!wait_for_resume_needed)
        resume ();

    if (wait_for_resume_needed && Environment.can_block_at_load_time ()) {
        var scheduler = Gum.ScriptBackend.get_scheduler ();

        scheduler.disable_background_thread ();

        wait_for_resume_context = scheduler.get_js_context ();

        var ignore_scope = new ThreadIgnoreScope ();

        start (request);

        var loop = new MainLoop (wait_for_resume_context, true);
        wait_for_resume_loop = loop;

        wait_for_resume_context.push_thread_default ();
        loop.run ();
        wait_for_resume_context.pop_thread_default ();

        scheduler.enable_background_thread ();

        ignore_scope = null;
    } else {
        start (request);
    }

    if (result != null) {
        try {
            *result = request.future.wait ();
        } catch (Gee.FutureError e) {
            *result = -1;
        }
    }
}
```
Gadget启动时会根据指定路径去搜索配置文件，默认配置文件如下
```js
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27042,
    "on_port_conflict": "fail",
    "on_load": "wait"
  }
}
```
即使用listen模式，监听在27042端口并等待连接。除了listen以外，还支持以下几种模式:
- connect: Gadget启动后主动连接到指定地址
- script: 启动后直接加载指定的JavaScript文件
- script-directory: 启动后加载指定目录下的所有JavaScript文件
### 三、ART Hook
