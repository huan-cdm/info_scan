#! python3

import atexit
import json
from queue import Queue
import sys
from threading import Thread, Event, Lock
from subprocess import Popen, PIPE
from os import path, environ

from .__pkginfo__ import __version__

DENO_EXECUTABLE = "deno"
VM_SERVER = path.join(path.dirname(__file__), "vm-server/index.js")
VM_WORKER = path.join(path.dirname(__file__), "vm-server/vendor/deno.land/x/worker_vm@v0.2.0/worker.ts")

def eval(code, **options):
    """A shortcut to eval JavaScript.

    :param str code: The code to be run.
    :param options: Additional options sent to :class:`VM`.

    This function will create a :class:`VM`, run the code, and return the
    result.
    """
    with VM(**options) as vm:
        # https://github.com/PyCQA/pylint/issues/3450
        # pylint: disable=no-member
        return vm.run(code)

DEFAULT_BRIDGE = None

def default_bridge():
    global DEFAULT_BRIDGE
    if DEFAULT_BRIDGE is not None:
        return DEFAULT_BRIDGE

    DEFAULT_BRIDGE = VMServer().start()
    return DEFAULT_BRIDGE

@atexit.register	
def close():
    if DEFAULT_BRIDGE is not None:
        try:
            DEFAULT_BRIDGE.close()
        except RuntimeError:
            pass

class BaseVM:
    """BaseVM class, containing some common methods for VMs.
    """
    def __init__(self, server=None, console="off"):
        """
        :param VMServer server: Optional. If provided, the VM will be created
            on the server. Otherwise, the VM will be created on a default
            server, which is started on the first creation of VMs.
        """
        if server is None:
            server = default_bridge()
        self.bridge = server
        self.id = None
        self.event_que = None
        self.console = console

    def __enter__(self):
        """This class can be used as a context manager, which automatically
        :meth:`create` when entering the context.
        """
        self.create()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """See :meth:`destroy`"""
        self.destroy()

    def before_create(self, data):
        """Overwrite. Extend data before creating the VM."""
        pass

    def create(self):
        """Create the VM."""
        data = {"action": "create"}
        self.before_create(data)
        self.id = self.communicate(data)
        self.bridge.add_vm(self)
        self.after_create(data)
        return self

    def after_create(self, data):
        pass

    def destroy(self):
        """Destroy the VM."""
        self.communicate({"action": "destroy"})
        self.bridge.remove_vm(self)
        self.id = None
        return self

    def communicate(self, data):
        """Communicate with server. Wraps :meth:`VMServer.communicate` so we
        can add additional properties to data.

        This method would raise an :class:`VMError` if vm-server response an
        error.
        """
        if self.id is None and data["action"] != "create":
            raise VMError("VM is not created yet.")
        data["vmId"] = self.id
        data = self.bridge.communicate(data)
        if data["status"] != "success":
            raise VMError(data["error"])
        return data.get("value")

class VM(BaseVM):
    """Create VM instance."""
    def __init__(self, code="", server=None, console="off", **options):
        """
        :param str code: Optional JavaScript code to run after creating
            the VM. Useful to define some functions.

        :param VMServer server: Optional VMServer. See :class:`BaseVM`
            for details.

        :param str console: Optional. Can be "off", "inherit", "redirect". If set to "redirect", console events would be put into :attr:`event_que`.

        :param options: Other options for VM.
        """
        super().__init__(server=server, console=console)
        self.id = None
        self.options = options
        self.event_que = Queue()
        """A :class:`queue.Queue` object containing console events.

        An event is a :class:`dict` and you can get the text value with:

        .. code:: python

            event = self.event_que.get()
            text = event.get("value")

        """
        self.initial_code = code

    def before_create(self, data):
        """Create VM."""
        data.update(type="VM", options=self.options)

    def after_create(self, data):
        """Run initial code."""
        if self.initial_code:
            self.run(self.initial_code)

    def run(self, code):
        """Execute JavaScript and return the result.

        If the server responses an error, a :class:`VMError` will be raised.
        """
        return self.communicate({"action": "run", "code": code})

    def call(self, function_name, *args):
        """Call a function and return the result.

        :param str function_name: The function to call.
        :param args: Function arguments.

        ``function_name`` may include "." to call functions on an object.
        """
        return self.communicate({
            "action": "call",
            "functionName": function_name,
            "args": args
            })

class VMServer:
    """VMServer class, represent vm-server. See :meth:`start` for details."""
    def __init__(self, command=None):
        """
        :param str command: the command to spawn subprocess. If not set, it
            would use:

            1. Environment variable ``DENO_EXECUTABLE``
            2. "deno"
        """

        self.closed = None
        self.process = None
        self.vms = {}
        self.poll = {}
        self.write_lock = Lock()
        self.poll_lock = Lock()
        self.inc = 1
        if command is None:
            command = environ.get("DENO_EXECUTABLE", DENO_EXECUTABLE)
        self.command = command

    def __enter__(self):
        """This class can be used as a context manager, which automatically
        :meth:`start` the server.

        .. code-block:: python

            server = VMServer()
            server.start()
            # create VMs on the server...
            server.close()

        vs.

        .. code-block:: python

            with VMServer() as server:
                # create VMs on the server...
        """
        return self.start()

    def __exit__(self, exc_type, exc_value, traceback):
        """See :meth:`close`."""
        self.close()

    def start(self):
        """Spawn a subprocess and run vm-server.

        vm-server is a REPL server, which allows us to connect to it with
        stdios. You can find the script at ``deno_vm/vm-server`` (`Github
        <https://github.com/eight04/deno_vm/tree/master/deno_vm/vm-server>`__).

        Communication using JSON::

            > {"id": 1, "action": "create", "type": "VM"}
            {"id": 1, "status": "success"}

            > {"id": 2, "action": "run", "code": "var a = 0; a += 10; a"}
            {"id": 2, "status": "success", "value": 10}

            > {"id": 3, "action": "xxx"}
            {"id": 3, "status": "error", "error": "Unknown action: xxx"}

        A :class:`VMError` will be thrown if the process cannot be spawned.
        """
        if self.closed:
            raise VMError("The VM is closed")

        args = [
            self.command,
            "run",
            "--unstable-worker-options",
            # "--allow-net=deno.land",
            f"--allow-read={VM_WORKER}",
            VM_SERVER]
        try:
            self.process = Popen(args, bufsize=0, stdin=PIPE, stdout=PIPE) # pylint: disable=consider-using-with
        except FileNotFoundError as err:
            raise VMError(f"Failed starting VM server. '{self.command}' is unavailable.") from err
        except Exception as err:
            raise VMError("Failed starting VM server") from err

        def reader():
            for data in self.process.stdout:
                try:
                    # FIXME: https://github.com/PyCQA/pylint/issues/922
                    data = json.loads(data.decode("utf-8")) or {}
                except json.JSONDecodeError:
                    # the server is down?
                    self.close()
                    return

                if data["type"] == "response":
                    with self.poll_lock:
                        self.poll[data["id"]][1] = data
                        self.poll[data["id"]][0].set()

                elif data["type"] == "event":
                    try:
                        vm = self.vms[data["vmId"]]
                    except KeyError:
                        # the vm is destroyed
                        continue

                    if data["name"] == "console.log":
                        if vm.console == "redirect":
                            vm.event_que.put(data)

                        elif vm.console == "inherit":
                            sys.stdout.write(data.get("value", "") + "\n")

                    elif data["name"] == "console.error":
                        if vm.console == "redirect":
                            vm.event_que.put(data)

                        elif vm.console == "inherit":
                            sys.stderr.write(data.get("value", "") + "\n")

        Thread(target=reader, daemon=True).start()

        data = self.communicate({"action": "ping"})
        if data["status"] == "error":
            raise VMError("Failed to start: " + data["error"])
        self.closed = False
        return self

    def close(self):
        """Close the server. Once the server is closed, it can't be 
        re-open."""
        if self.closed:
            return self
        try:
            data = self.communicate({"action": "close"})
            if data["status"] == "error":
                raise VMError("Failed to close: " + data["error"])
        except OSError:
            # the process is down?
            pass
        self.process.communicate()
        self.process = None
        self.closed = True

        with self.poll_lock:
            for event, _data in self.poll.values():
                event.set()
        return self

    def add_vm(self, vm):
        self.vms[vm.id] = vm

    def remove_vm(self, vm):
        del self.vms[vm.id]

    def generate_id(self):
        """Generate unique id for each communication."""
        inc = self.inc
        self.inc += 1
        return inc

    def communicate(self, data):
        """Send data to subprocess and return the response.

        :param dict data: must be json-encodable and follow vm-server's
            protocol. An unique id is automatically assigned to data.

        This method is thread-safe.
        """
        id = self.generate_id()

        data["id"] = id
        text = json.dumps(data) + "\n"

        event = Event()

        with self.poll_lock:
            self.poll[id] = [event, None]

        # FIXME: do we really need lock for write?
        with self.write_lock:
            self.process.stdin.write(text.encode("utf-8"))

        event.wait()

        with self.poll_lock:
            data = self.poll[id][1]
            del self.poll[id]
        return data

class VMError(Exception):
    """Errors thrown by VM."""
    pass
