// Method Tracer
// Receives {className, methodName} via rpc.exports.trace() or send() from Python side
// Hooks all overloads and logs arguments + return values

var tracedMethods = [];

function traceMethod(className, methodName) {
  Java.perform(function () {
    try {
      var clazz = Java.use(className);
      var overloads = clazz[methodName].overloads;
      if (!overloads || overloads.length === 0) {
        send({ hook: 'method_tracer', error: 'No overloads found for ' + className + '.' + methodName });
        return;
      }
      overloads.forEach(function (overload) {
        overload.implementation = function () {
          var args = Array.prototype.slice.call(arguments).map(function (a) {
            try { return a ? a.toString() : String(a); } catch (e) { return '<unreadable>'; }
          });
          var ret;
          try {
            ret = overload.apply(this, arguments);
          } catch (e) {
            send({
              hook: 'method_tracer',
              class: className,
              method: methodName,
              args: args,
              exception: e.toString()
            });
            throw e;
          }
          var retStr;
          try { retStr = ret ? ret.toString() : String(ret); } catch (e) { retStr = '<unreadable>'; }
          send({
            hook: 'method_tracer',
            class: className,
            method: methodName,
            signature: overload.argumentTypes.map(function (t) { return t.className; }).join(', '),
            args: args,
            return: retStr
          });
          return ret;
        };
      });
      tracedMethods.push(className + '.' + methodName);
      send({ hook: 'method_tracer', status: 'tracing ' + className + '.' + methodName + ' (' + overloads.length + ' overloads)' });
    } catch (e) {
      send({ hook: 'method_tracer', error: e.toString(), class: className, method: methodName });
    }
  });
}

rpc.exports = {
  trace: function (className, methodName) {
    traceMethod(className, methodName);
  },
  list: function () {
    return tracedMethods;
  }
};

send({ status: 'Method tracer loaded — call rpc.exports.trace(className, methodName) to hook' });
