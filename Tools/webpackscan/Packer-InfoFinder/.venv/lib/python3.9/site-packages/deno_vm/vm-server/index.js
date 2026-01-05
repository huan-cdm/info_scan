import { TextLineStream } from "https://deno.land/std@0.203.0/streams/mod.ts";
import { VM } from "https://deno.land/x/worker_vm@v0.2.0/mod.ts";

const vmList = collection();
const lines = Deno.stdin.readable
  .pipeThrough(new TextDecoderStream())
  .pipeThrough(new TextLineStream());

for await (const line of lines) {
  handleLine(line);
}

function handleLine(line) {
	let result, err;
	const input = JSON.parse(line);
	try {
		result = processLine(input);
	} catch (_err) {
		err = _err;
	}
	if (err) {
		result = {status: "error", error: err.message || err};
	} else {
		result = result || {};
		result.status = "success";
	}
	result.id = input.id;
	result.type = "response";
	Promise.resolve(result.value)
		.then(value => {
			result.value = value;
			console.log(JSON.stringify(result));
		})
		.catch(error => {
			result.status = "error";
			result.error = error.message || error;
			delete result.value;
			console.log(JSON.stringify(result));
		});
}

function processLine(input) {
	switch (input.action) {
		case "ping":
			return;
			
		case "close":
			setTimeout(() => Deno.exit(0));
			return;
			
		case "create":
			return createVM(input);
			
		case "destroy":
			return destroyVM(input);
			
		default: {
      const vm = vmList.get(input.vmId);
      if (!vm[input.action]) {
        throw new Error("(vm-server) unknown action: " + input.action);
      }
      return vm[input.action](input);
    }
	}
}

function createVM(input) {
	switch (input.type) {
		case "VM":
			return createNormalVM(input);
			
		default:
			throw new Error("(vm-server) unknown VM type: " + input.type);
	}
}

function destroyVM(input) {
  vmList.get(input.vmId).destroy();
	vmList.remove(input.vmId);
}

function createNormalVM(input) {
	const _vm = new VM(input.options);
	if (input.code) {
		_vm.run(input.code);
	}
	const vm = {
		run({code}) {
			return {
				value: _vm.run(code)
			};
		},
		call({functionName, args}) {
			return {
				value: _vm.call(functionName, ...args)
			};
		},
    destroy() {
      _vm.close();
    }
	};
  const id = vmList.add(vm);
  _vm.addEventListener("console", e => {
    const event = {
      vmId: id,
      type: "event",
      name: `console.${e.detail.method}`,
      value: e.detail.args.map(String).join(" ")
    }
    console.log(JSON.stringify(event));
  });
	return {
		value: id
	};
}

function collection() {
	let inc = 1;
	const hold = Object.create(null);
	return {
		add(item) {
			hold[inc] = item;
			return inc++;
		},
		remove(id) {
			if (!(id in hold)) {
				throw new Error(`(vm-server) failed removing VM, id=${id}`);
			}
			delete hold[id];
		},
		get(id) {
			if (!(id in hold)) {
				throw new Error(`(vm-server) failed getting VM, id=${id}`);
			}
			return hold[id];
		},
		has(id) {
			return id in hold;
		}
	};
}
