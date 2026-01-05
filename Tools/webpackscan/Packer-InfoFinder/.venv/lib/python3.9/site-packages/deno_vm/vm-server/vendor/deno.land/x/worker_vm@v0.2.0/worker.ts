{
  const _console = console;
  self.console = new Proxy(_console, {
    get: (target, prop) => {
      return (...args: any[]) => {
        // @ts-ignore
        self.postMessage({
          type: "console",
          method: prop,
          args: JSON.parse(JSON.stringify(args))
        });
      };
    }
  });


  self.addEventListener("message", (e_) => {
    const e = e_ as MessageEvent;
    const code = e.data.code;
    let result: any;
    try {
      result = (0, eval)(code);
      if (result?.then) {
        result
          .then((r: any) => {
            // @ts-ignore
            self.postMessage({
              id: e.data.id,
              result: r
            });
          })
          .catch((err: any) => {
            // @ts-ignore
            self.postMessage({
              id: e.data.id,
              error: String(err)
            });
          });
        return;
      }
      // @ts-ignore
      self.postMessage({
        id: e.data.id,
        result
      });
    } catch (err) {
      // @ts-ignore
      self.postMessage({
        id: e.data.id,
        error: String(err)
      });
      return;
    }
  });
}
