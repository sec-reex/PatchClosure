/**
 * @kind table
 * @id patchclosure/py-coreach
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

string srcRe() { result = "{src_re}" }
string guardRe() { result = "{guard_re}" }
string sinkRe() { result = "{sink_re}" }

predicate sourceNode(DataFlow::Node n) {
  exists(Function f, DataFlow::ParameterNode p |
    f.getName().regexpMatch(srcRe()) and
    (
      f.getArg(_) = p.getParameter() or
      f.getVararg() = p.getParameter() or
      f.getKwarg() = p.getParameter() or
      f.getAKeywordOnlyArg() = p.getParameter()
    ) and
    n = p
  )
}

predicate namedCall(DataFlow::CallCfgNode c, string kind) {
  kind = "sink" and
  (
    c.getFunction().asCfgNode().(NameNode).getId().regexpMatch(sinkRe())
    or
    c.(DataFlow::MethodCallNode).getMethodName().regexpMatch(sinkRe())
  )
  or
  kind = "guard" and
  (
    c.getFunction().asCfgNode().(NameNode).getId().regexpMatch(guardRe())
    or
    c.(DataFlow::MethodCallNode).getMethodName().regexpMatch(guardRe())
  )
}

predicate sinkArg(DataFlow::Node n) {
  exists(DataFlow::CallCfgNode c | namedCall(c, "sink") and n = c.getArg(_))
}

predicate guardArg(DataFlow::Node n) {
  exists(DataFlow::CallCfgNode c | namedCall(c, "guard") and n = c.getArg(_))
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
  sinkCalls = count(DataFlow::CallCfgNode c | namedCall(c, "sink")) and
  guardCalls = count(DataFlow::CallCfgNode c | namedCall(c, "guard")) and
  fSink = count(DataFlow::Node a, DataFlow::Node b | FlowSink::flow(a, b)) and
  fGuard = count(DataFlow::Node a, DataFlow::Node b | FlowGuard::flow(a, b))
select sinkCalls, guardCalls, fSink, fGuard
