/**
 * @kind table
 * @id patchclosure/go-coreach
 */

import go

string srcRe() { result = "{src_re}" }
string guardRe() { result = "{guard_re}" }
string sinkRe() { result = "{sink_re}" }

predicate sourceNode(DataFlow::Node n) {
  exists(FuncDef f, Parameter p |
    f.getName().regexpMatch(srcRe()) and
    p = f.getAParameter() and
    n = DataFlow::parameterNode(p)
  )
}

predicate sinkArg(DataFlow::Node n) {
  exists(DataFlow::CallNode c |
    c.getCalleeName().regexpMatch(sinkRe()) and
    n = c.getAnArgument()
  )
}

predicate guardArg(DataFlow::Node n) {
  exists(DataFlow::CallNode c |
    c.getCalleeName().regexpMatch(guardRe()) and
    n = c.getAnArgument()
  )
}

module ToSink implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { sourceNode(n) }
  predicate isSink(DataFlow::Node n) { sinkArg(n) }
}

module ToGuard implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { sourceNode(n) }
  predicate isSink(DataFlow::Node n) { guardArg(n) }
}

module FlowSink = TaintTracking::Global<ToSink>;
module FlowGuard = TaintTracking::Global<ToGuard>;

from int sinkCalls, int guardCalls, int fSink, int fGuard
where
  sinkCalls = count(DataFlow::CallNode c | c.getCalleeName().regexpMatch(sinkRe())) and
  guardCalls = count(DataFlow::CallNode c | c.getCalleeName().regexpMatch(guardRe())) and
  fSink = count(DataFlow::Node a, DataFlow::Node b | FlowSink::flow(a, b)) and
  fGuard = count(DataFlow::Node a, DataFlow::Node b | FlowGuard::flow(a, b))
select sinkCalls, guardCalls, fSink, fGuard
