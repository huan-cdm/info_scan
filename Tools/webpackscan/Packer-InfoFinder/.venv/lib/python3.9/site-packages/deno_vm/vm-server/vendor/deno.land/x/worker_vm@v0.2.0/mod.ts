export interface ConsoleEvent extends CustomEvent {
  detail: {
    type: "console";
    method: string;
    args: any[];
  };
}

export interface VMEventMap {
  console: ConsoleEvent;
}

export interface VMEventTarget extends EventTarget {
  addEventListener<K extends keyof VMEventMap>(
    type: K,
    listener: (this: VM, ev: VMEventMap[K]) => any,
    options?: boolean | AddEventListenerOptions
  ): void;
  addEventListener(
    type: string,
    listener: EventListenerOrEventListenerObject,
    options?: boolean | AddEventListenerOptions
  ): void;
  removeEventListener<K extends keyof VMEventMap>(
    type: K,
    listener: (this: VM, ev: VMEventMap[K]) => any,
    options?: boolean | EventListenerOptions
  ): void;
  removeEventListener(
    type: string,
    listener: EventListenerOrEventListenerObject,
    options?: boolean | EventListenerOptions
  ): void;
}

/**
 * This class extends EventTarget. You can listen to "console" event to get
 * console output from the worker.
 *
 * @event VM#console
 * @type {ConsoleEvent}
 */
export class VM extends EventTarget implements VMEventTarget {
  worker: Worker;
  id: number;
  messagePool: Map<number, { resolve: (value: any) => void, reject: (reason?: any) => void, ts: number, timeoutId: number }>;
  dead: boolean;
  timeoutMs: number;
  /**
   * Create a new worker VM instance.
   *
   * @param timeoutMs Timeout for each run() call in milliseconds. Default: 30 seconds.
   */
  constructor({timeoutMs = 30 * 1000}: {timeoutMs?: number} = {}) {
    super();
    this.worker = new Worker(new URL("./worker.ts", import.meta.url), {
      type: "module",
      deno: {
        permissions: "none"
      }
    });
    this.worker.addEventListener("message", (e) => {
      if (e.data.type === "console") {
        this.dispatchEvent(new CustomEvent("console", {
          detail: e.data
        }));
        return;
      }
      if (!this.messagePool.has(e.data.id)) {
        return;
      }
      const { resolve, reject, timeoutId } = this.messagePool.get(e.data.id)!;
      if (e.data.error) {
        reject(e.data.error);
      } else {
        resolve(e.data.result);
      }
      clearTimeout(timeoutId);
      this.messagePool.delete(e.data.id);
    });
    const onerror = (e: Event | ErrorEvent) => {
      const err = new Error((e as ErrorEvent).message || (e as ErrorEvent).error || "Unknown error");
      this.close(err);
    };
    this.worker.addEventListener("error", onerror);
    this.worker.addEventListener("messageerror", onerror);
    this.id = 1;
    this.messagePool = new Map;
    this.dead = false;
    this.timeoutMs = timeoutMs;
  }
  /**
   * Run code in the VM and return the result.
   *
   * @param code Code to run.
   * @returns Promise that resolves to the result of the code.
   *
   * If the code throws an error, the promise will be rejected with the error.
   * If the code takes longer than the timeout, the promise will be rejected with an error.
   * The code may returns a promise, which will be awaited.
   */
  run(code: string) {
    return new Promise((resolve, reject) => {
      if (this.dead) throw new Error("VM is closed");
      const id = this.id++;
      const timeoutId = setTimeout(() => {
        reject(new Error("Timeout"));
        this.messagePool.delete(id);
      }, this.timeoutMs);
      this.messagePool.set(id, { resolve, reject, ts: Date.now(), timeoutId });
      this.worker.postMessage({
        id,
        code
      });
    });
  }
  /**
   * Call a function in the VM and return the result. This method uses run() under the hood.
   *
   * @param name Name of the function to run. It can be any identifer, including a property access.
   * @param args Arguments to pass to the function.
   */
  call(name: string, ...args: any[]) {
    return this.run(`${name}(${args.map((arg) => JSON.stringify(arg)).join(",")})`);
  }
  /**
   * Close the VM.
   *
   * All pending promises will be rejected with an error.
   * The VM will be unusable after this.
   */
  close(err?: Error) {
    if (!err) {
      err = new Error("VM is closed");
    }
    this.worker.terminate();
    this.dead = true;
    for (const { reject, timeoutId } of this.messagePool.values()) {
      reject(err);
      clearTimeout(timeoutId);
    }
    this.messagePool.clear();
  }
}
