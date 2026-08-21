/**
 * @kind table
 * @id patchclosure/java-coreach
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

string srcRe() { result = "{src_re}" }
string guardRe() { result = "{guard_re}" }
string sinkRe() { result = "{sink_re}" }

predicate sourceNode(DataFlow::Node n) {
  exists(Parameter p |
    p.getCallable().getName().regexpMatch(srcRe()) and
    n.asParameter() = p
  )
}

predicate sinkArg(DataFlow::Node n) {
  exists(MethodCall c |
    c.getMethod().getName().regexpMatch(sinkRe()) and
    n.asExpr() = c.getAnArgument()
  )
}

predicate guardArg(DataFlow::Node n) {
  exists(MethodCall c |
    c.getMethod().getName().regexpMatch(guardRe()) and
    n.asExpr() = c.getAnArgument()
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
  sinkCalls = count(MethodCall c | c.getMethod().getName().regexpMatch(sinkRe())) and
  guardCalls = count(MethodCall c | c.getMethod().getName().regexpMatch(guardRe())) and
  fSink = count(DataFlow::Node a, DataFlow::Node b | FlowSink::flow(a, b)) and
  fGuard = count(DataFlow::Node a, DataFlow::Node b | FlowGuard::flow(a, b))
select sinkCalls, guardCalls, fSink, fGuard
