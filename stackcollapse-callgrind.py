#!/usr/bin/python
#
# stackcollapse-callgrind.py - collapse Callgrind Format [1] callstack events
# into single lines.
#
# [1] https://valgrind.org/docs/manual/cl-format.html
#
# USAGE: ./stackcollapse-callgrind.py callgrind_file > outfile
#
# Example input:
#
# # callgrind format
# events: Instructions
#
# fl=(1) file1.c
# fn=(1) main
# 16 20
# cfn=(2) func1
# calls=1 50
# 16 400
# cfi=(2) file2.c
# cfn=(3) func2
# calls=3 20
# 16 400
#
# fn=(2)
# 51 100
# cfi=(2)
# cfn=(3)
# calls=2 20
# 51 300
#
# fl=(2)
# fn=(3)
# 20 700
#
# Example output:
#
# file1.c#main 20
# file1.c#main;file1.c#func1 100
# file1.c#main;file1.c#func1;file2.c#func2 300
# file1.c#main;file2.c#func2 400
#
# Input may contain many stack trace events from many processes/threads.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at docs/cddl1.txt or
# http://opensource.org/licenses/CDDL-1.0.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at docs/cddl1.txt.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# 20-Mar-2022    Johan Gunnarsson    Created this.

import argparse
import re
import collections

ob = {}
fl = {}
fn = {}
functions = {}


def lookup(table, name):
    match = re.match(r"(\([0-9]+\)) (.+)", name)
    if match:
        num, val, = match.groups()
        if num not in table:
            table[num] = val
        return val
    match = re.match(r"(\([0-9]+\))", name)
    if match:
        num, = match.groups()
        if num not in table:
            raise Exception(num + " not found")
        return table[num]
    return name


def lookup_ob(name):
    return lookup(ob, name)


def lookup_fl(name):
    return lookup(fl, name)


def lookup_fn(name):
    return lookup(fn, name)


class Function:
    def __init__(self, objectname, filename, name):
        self.objectname = objectname
        self.filename = filename
        self.name = name

        self.callfunctions = set()
        self.calls = list()
        self.callcosts = {}
        self.callcounts = {}

        self.cost = 0

        self.total_call_cost = 0
        self.total_call_count = 0

    def __repr__(self):
        return "{}#{}#{}".format(self.objectname, self.filename, self.name)

    def __str__(self):
        return "{}#{}".format(self.filename, self.name)

    def __eq__(self, o):
        return o.objectname == self.objectname and \
               o.filename == self.filename and \
               o.name == self.name

    def __hash__(self):
        return hash(repr(self))

    def add_call(self, callee, count):
        if callee not in self.callfunctions:
            self.calls.append(callee)
            self.callcosts[callee] = 0
            self.callcounts[callee] = 0
            self.callfunctions.add(callee)

        # Ignore recursive calls
        if self == callee:
            return

        self.callcosts[callee] += 0
        self.callcounts[callee] += count

        # Total number of calls to callee
        callee.total_call_count += count

    def add_callcost(self, callee, cost):
        # Ignore recursive calls
        if self == callee:
            return

        self.callcosts[self.calls[-1]] += cost

        # Total time spent in callee
        callee.total_call_cost += cost

    def add_cost(self, cost):
        self.cost += cost

    def print_stacks(self, stack, count=0, cost=0):
        signature = str(self)
        if signature in stack:
            return

        stack.append(signature)
        if len(self.calls) > 0:
            if self.total_call_count > 0:
                assert count <= self.total_call_count
                scale = count / self.total_call_count
            else:
                scale = 1.0

            # Scale exclusive cost
            print(";".join(stack), round(scale * self.cost))

            for f in self.calls:
                callcost = self.callcosts[f]
                callcount = self.callcounts[f]

                # Scale inclusive cost
                f.print_stacks(stack, callcount, round(scale * callcost))
        else:
            # Leaf node
            print(";".join(stack), cost)
        stack.pop()


def lookup_f(ob, fl, fn):
    obstr = lookup_ob(ob)
    flstr = lookup_fl(fl)
    fnstr = lookup_fn(fn)
    func = Function(obstr, flstr, fnstr)
    signature = str(func)
    if signature not in functions:
        functions[signature] = func
    return functions[signature]


def calls(state, param):
    costs = param.split(" ")
    caller = lookup_f(state["ob"], state["fl"], state["fn"])
    callee = lookup_f(state["cob"], state["cfi"], state["cfn"])
    # print("calls", caller, callee, costs)
    caller.add_call(callee, int(costs[0]))


def callcost(state, param):
    costs = param.split(" ")
    caller = lookup_f(state["ob"], state["fl"], state["fn"])
    callee = lookup_f(state["cob"], state["cfi"], state["cfn"])
    # print("callcost", caller, callee, costs)
    caller.add_callcost(callee, int(costs[1]))


def cost(state, param):
    costs = param.split(" ")
    function = lookup_f(state["ob"], state["fl"], state["fn"])
    # print("cost", function, costs)
    function.add_cost(int(costs[1]))


def parse_body(queue):
    alias = {
        "cfl": "cfi",
    }
    state = {
        "ob": "???",
        "fl": "???",
        "fn": "???",
    }
    in_call = False

    while queue:
        line = queue[0].strip()
        if line.startswith("#"):
            queue.popleft()
            continue
        if len(line) == 0:
            queue.popleft()
            continue

        match = re.match("([a-z]+)=(.*)", line)
        if match:
            queue.popleft()
            key, value, = match.groups()
            if key in alias:
                key = alias[key]
            state[key] = value

            if key == "fi" or key == "fe":
                # We don't care about inlining, but still have to lookup name
                lookup_fl(value)
            if key == "calls":
                # Default cob and cfi
                if "cob" not in state and "ob" in state:
                    state["cob"] = state["ob"]
                if "cfi" not in state and "fl" in state:
                    state["cfi"] = state["fl"]

                calls(state, value)
                in_call = True
        else:
            # Cost line?
            match = re.match(r"[0-9\-\+\*]+", line)
            if match:
                queue.popleft()
                if in_call:
                    callcost(state, line)
                    in_call = False

                    # Clear call state after call
                    if "cob" in state:
                        del state["cob"]
                    if "cfi" in state:
                        del state["cfi"]
                else:
                    cost(state, line)
            else:
                # End of body
                break


def parse_header(queue):
    state = {}

    while queue:
        line = queue[0].strip()
        if line.startswith("#"):
            queue.popleft()
            continue
        if len(line) == 0:
            queue.popleft()
            continue

        match = re.match("([a-z]+): (.*)", line)
        if match:
            queue.popleft()
            key, value, = match.groups()
            state[key] = value
        else:
            # End of headers
            break


def main(queue):
    parse_header(queue)
    parse_body(queue)
    parse_header(queue)

    # Traverse call graph from root functions
    for func in functions.values():
        if func.total_call_count == 0 and len(func.calls) > 0:
            func.print_stacks(collections.deque())


parser = argparse.ArgumentParser()
parser.add_argument('input_file', nargs='+',
                    type=argparse.FileType('r'),
                    help='Callgrind input files')
args = parser.parse_args()

main(collections.deque(args.input_file[0]))
