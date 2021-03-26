/**
 * Authors: Tomoya Tanjo
 * Copyright: © 2021 Tomoya Tanjo
 * License: Apache-2.0
 */
module medal_hook.main;

import std;

import dyaml;

int medalHookMain(string[] args)
{
    string[] hookFiles;

    auto helpInfo = args.getopt(
        config.caseSensitive,
        "hook", "Specify a hook file", &hookFiles,
    );

    if (helpInfo.helpWanted || args.length != 2)
    {
        immutable baseMessage = format!(q"EOS
            medal-hook
            Usage: %s [options] <network.yml>
EOS".outdent[0..$-1])(args[0].baseName);
        defaultGetoptPrinter(baseMessage, helpInfo.options);
        return 0;
    }

    auto netFile = args[1];
    if (!netFile.exists)
    {
        stderr.writefln("File not found: %s", netFile);
        return 1;
    }
    auto net = Loader.fromFile(netFile).load;

    foreach(f; hookFiles)
    {
        if (!f.exists)
        {
            stderr.writefln("File not found: %s", f);
            return 1;
        }
    }

    try
    {
        auto appliedNetwork = hookFiles.map!(f => Loader.fromFile(f).load).fold!apply(net);
        auto app = appender!string;
        dumper.dump(app, appliedNetwork);
        writeln(app[]);
    }
    catch (MedalHookException e)
    {
        stderr.writefln("%s:%s:%s: %s", e.file, e.line, e.column, e.msg);
        return 1;
    }
    return 0;
}

auto apply(ref Node base, Node hook)
{
    auto app = base.edig("application").get!string;
    auto hooks = hook.edig("hooks");
    auto hs = hooks.sequence.filter!(h => h.edig("target").get!string == app);
    if (hs.empty) return base;
    auto h = hs.front;

    auto workdir = hook.startMark.name.dirName;
    foreach(Node cond; h.dig("precondition", []))
    {
        auto cmd = cond.get!string.replace("~(target)", base.startMark.name.absolutePath);
        auto ls = executeShell(cmd, null, Config.none, size_t.max, workdir);
        medalHookEnforce(ls.status == 0,
                         format!"Precondition `%s` does not hold (status: %s, output: `%s`)"(cmd, ls.status, ls.output),
                         cond);
    }

    auto result = h.edig("operations").sequence.fold!applyOperation(base);
    if (auto ah = "applied-hooks" in result)
    {
        ah.add(hook.edig("id"));
    }
    else
    {
        result.add("applied-hooks", Node([hook.edig("id")]));
    }
    return result;
}

Node applyOperation(Node base, Node op)
{
    auto type = op.edig("type").get!string;
    switch(type)
    {
    case "replace-env":
        auto t = base.edig("type");
        medalHookEnforce(t == "network", format!"Unsupported type: %s"(t.get!string), t);
        auto newEnv = op.edig("env").sequence
                                    .map!(e => tuple(e.edig("name").get!string,
                                                     e.edig("value").get!string))
                                    .assocArray;
        auto replacedEnv =
            base.edig(["configuration", "env"])
                .sequence
                .map!((e) {
                    auto name = e.edig("name").get!string;
                    auto oldValue = e.edig("value").get!string;
                    string value;
                    if (auto val = name in newEnv)
                    {
                        value = (*val).replace("~(self)", oldValue);
                        newEnv.remove(name);
                    }
                    else
                    {
                        value = oldValue;
                    }
                    return tuple(name, value);
                })
                .assocArray;
        auto resultedEnv = chain(newEnv.byPair, replacedEnv.byPair)
                            .map!((p) {
                                Node n;
                                n.add("name", p.key);
                                n.add("value", p.value);
                                return n;
                            })
                            .array;
        base["configuration"]["env"] = Node(resultedEnv);
        return base;
    case "replace-transition":
        auto t = base.edig("type");
        medalHookEnforce(t == "network", format!"Unsupported type: %s"(t.get!string), t);
        auto target = op.edig("target").get!string;
        auto rng = base.edig("transitions").sequence
                                           .enumerate
                                           .find!(t => t.value.edig("name") == target);
        medalHookEnforce(!rng.empty, "No such transition: "~target, base["transitions"]);
        base["transitions"][rng.front.index] = op.edig("transition");
        base["transitions"][rng.front.index]["name"] = target;
        return base;
    case "add-transitions":
        auto t = base.edig("type");
        medalHookEnforce(t == "network", format!"Unsupported type: %s"(t.get!string), t);
        if (auto trs = "transitions" in op)
        {
            trs.sequence.each!((t) {
                if ("transitions" !in base)
                {
                    base["transitions"] = Node((Node[]).init);
                }
                t.expandTransition(base).each!(tt => base["transitions"].add(tt));
            });
        }
        if (auto on = true in op)
        {
            if (auto bon_ = true in base)
            {
                auto bon = *bon_;
                if (auto suc = "success" in *on)
                {
                    suc.sequence.each!((t) {
                        if ("success" !in bon)
                        {
                            bon["success"] = Node((Node[]).init);
                        }
                        t.expandTransition(base).each!(tt => bon["success"].add(tt));
                    });
                }
                if (auto fail = "failure" in *on)
                {
                    fail.sequence.each!((t) {
                        if ("failure" !in bon)
                        {
                            bon["failure"] = Node((Node[]).init);
                        }
                        t.expandTransition(base).each!(tt => bon["failure"].add(tt));
                    });
                }
                if (auto ex = "exit" in *on)
                {
                    ex.sequence.each!((t) {
                        if ("exit" !in bon)
                        {
                            bon["exit"] = Node((Node[]).init);
                        }
                        t.expandTransition(base).each!(tt => bon["exit"].add(tt));
                    });
                }
            }
            else
            {
                base[true] = *on;
            }
        }
        return base;
    case "add-out":
        auto t = base.edig("type");
        medalHookEnforce(t == "network", format!"Unsupported type: %s"(t.get!string), t);
        auto target = op.edig("target").get!string;
        if (target.isRegexPattern)
        {
            medalHookEnforce(!target.endsWith("g"), "Global pattern is not supported", op["target"]);
            auto expandPattern(Node baseOp, Captures!string c)
            {
                Node ret;
                ret.add("type", Node("add-out"));
                ret["target"] = Node(c.hit);
                auto cap = c[1];
                ret["out"] = Node(baseOp.edig("out")
                                        .sequence
                                        .map!((o) {
                                            Node newOut;
                                            newOut.add("place", o.edig("place")
                                                                 .get!string
                                                                 .replace("~1", cap));
                                            newOut.add("pattern", o.edig("pattern"));
                                            return newOut;
                                        })
                                        .array);
                return ret;
            }
            auto re = regex(target[1..$-1]);
            auto trs = base.edig("transitions").sequence;
            foreach(tr; trs.filter!(t => t.edig("name").get!string.matchFirst(re)))
            {
                auto cap = tr["name"].get!string.matchFirst(re);
                auto expandedOp = expandPattern(op, cap);
                base = applyOperation(base, expandedOp);
            }
        }
        else if (base.edig("name") == target)
        {
            auto current = base.dig("out", []).sequence.array;
            auto added = op.edig("out").sequence.array;
            // TODO: should not be overwrapped
            base["out"] = Node(current~added);
        }
        else
        {
            // limitation: does not support to add them to `on` transitions
            auto rng = base.edig("transitions")
                           .sequence
                           .filter!(t => t.edig("name") == target);
            medalHookEnforce(!rng.empty, "No such transition: "~target, base["transitions"]);
            auto current = rng.front.dig("out", []).sequence.array;
            auto added = op.edig("out").sequence.array;
            rng.front["out"] = Node(current~added);
        }
        return base;
    case "insert-before":
        auto t = base.edig("type");
        medalHookEnforce(t == "network", format!"Unsupported type: %s"(t.get!string), t);
        auto trs = base.edig("transitions");
        auto rng = trs.sequence
                      .filter!(t => t.edig("name") == op.edig("target"));
        medalHookEnforce(!rng.empty, "No such transition: "~op["target"].get!string, trs);
        auto target = rng.front;
        auto replaceMap = op.dig("in", [])
                            .sequence
                            .map!(pair => tuple(pair.edig("replaced").get!string,
                                                pair.edig("with").get!string))
                            .assocArray;
        target["in"] = Node(target.edig("in")
                                .sequence
                                .map!((p) {
                                    Node n;
                                    auto pl = p.edig("place").get!string;
                                    n.add("place", replaceMap.get(pl, pl));
                                    n.add("pattern", p.edig("pattern"));
                                    if (target.edig("type") == "invocation")
                                    {
                                        n.add("port-to", p.edig("port-to"));
                                    }
                                    return n;
                                })
                                .array);
        static replaceRef(string s, string from, string to)
        {
            return s.replace(format!"~(in.%s)"(from), format!"~(in.%s)"(to));
        }
        if (target.edig("type") == "shell")
        {
            target["command"] = target.edig("command")
                                    .get!string
                                    .reduce!((acc, p) {
                                        return replaceRef(acc, p.key, p.value);
                                    })(replaceMap.byPair);
        }
        if (auto o_ = "out" in target)
        {
            target["out"] = Node(o_.sequence
                                   .map!((p) {
                                      Node n;
                                      n.add("place", p.edig("place"));
                                      auto pat = p.edig("pattern").get!string;
                                      auto newPat =
                                         pat.matchAll(ctRegex!`~\(in\.(.+)\)`)
                                            .fold!((p, c) =>
                                                replaceRef(p,
                                                           c[1],
                                                           replaceMap.get(c[1], c[1]))
                                            )(pat);
                                      n.add("pattern", newPat);
                                      return n;
                                   })
                                   .array);
        }
        auto curTrs = trs.sequence.array;
        auto inserted = op.edig("transitions").sequence.array;
        base["transitions"] = Node(curTrs~inserted);
        return base;
    default:
        throw new Exception("Unsupported hook type: "~type);
    }
    assert(false);
}

Node[] expandTransition(Node node, Node base)
{
    auto type = base.edig("type");
    medalHookEnforce(type == "network", format!"Unsupported type for expand: %s"(type.get!string), type);
    if (node.edig("type") != "shell")
    {
        return [node];
    }

    Node[] nonExpandedIn;
    Node[] expandedIn;
    auto isExpandPattern = false;
    auto isGlobalPattern = false;
    Captures!string[] caps;
    foreach(inp; node.dig("in", []).sequence)
    {
        auto pl = inp.edig("place").get!string;
        if (pl.isRegexPattern)
        {
            medalHookEnforce(!isExpandPattern, "Only one regex pattern is allowed", inp["place"]);
            isExpandPattern = true;
            isGlobalPattern = pl.endsWith("g");
            auto end = isGlobalPattern ? pl.length-2 : pl.length-1;
            auto re = regex(pl[1..end]);
            enumeratePlaces(base)
                .filter!(p => p.matchFirst(re))
                .each!((p) {
                    Node n;
                    n.add("place", p);
                    n.add("pattern", inp.edig("pattern"));
                    expandedIn ~= n;
                    caps ~= p.matchFirst(re);
                });
        }
        else
        {
            nonExpandedIn ~= inp;
        }
    }

    if (!isExpandPattern)
    {
        return [node];
    }
    else if (isGlobalPattern)
    {
        auto pls = expandedIn.map!(i => format!"~(%s)"(i.edig("place").get!string))
                             .array;
        auto cmd = node.edig("command").get!string.replace("~@", pls.joiner(" ").array);
        Node ret;
        ret.add("name", node.edig("name"));
        ret.add("type", "shell");
        ret.add("in", nonExpandedIn~expandedIn);
        if (auto o = "out" in node)
        {
            ret.add("out", *o);
        }
        ret.add("command", cmd);
        return [ret];
    }
    else
    {
        Node[] results;
        foreach(idx; iota(expandedIn.length))
        {
            auto c = caps[idx].array;
            auto pats = [["~0", format!"~(%s)"(c[0])]];
            pats ~= enumerate(c[1..$], 1).map!(tpl => [format!"~%s"(tpl.index), tpl.value]).array;

            Node ret;
            auto name = node.edig("name").get!string;
            pats.each!(p => name = name.replace(p[0], p[1]));
            ret.add("name", name);

            ret.add("type", "shell");
            ret.add("in", nonExpandedIn~expandedIn[idx]);


            auto cmd = node.edig("command").get!string;
            pats.each!(p => cmd = cmd.replace(p[0], p[1]));
            ret.add("command", cmd);

            if (auto o = "out" in node)
            {
                auto newOut = o.sequence.map!((oo) {
                    Node out_;
                    auto pl = oo.edig("place").get!string;
                    pats.each!(p => pl = pl.replace(p[0], p[1]));
                    out_.add("place", pl);
                    out_.add("pattern", oo.edig("pattern"));
                    return out_;
                }).array;
                ret.add("out", Node(newOut));
            }
            results ~= ret;
        }
        return results;
    }
    assert(false);
}

auto enumerateTransitions(Node n)
{
    auto type = n.edig("type");
    medalHookEnforce(type == "network", format!"Unsupported type for enumerate transitions: %s"(type), type);
    return chain(n.dig("transitions",   []).sequence,
                 n.dig(["on", "success"], []).sequence,
                 n.dig(["on", "failure"], []).sequence,
                 n.dig(["on", "exit"],    []).sequence).array;
}

auto enumeratePlaces(Node node)
{
    auto places(Node n)
    {
        return chain(n.dig("in", []).sequence,
                     n.dig("out", []).sequence)
                .map!(n => n.edig("place").get!string)
                .array;
    }
    auto arr =  enumerateTransitions(node)
                    .map!(n => places(n))
                    .joiner
                    .array;
    return arr.sort.uniq.array;
}

auto dig(T)(Node node, string key, T default_)
{
    return dig(node, [key], default_);
}

auto dig(T)(Node node, string[] keys, T default_)
{
    Node ret = node;
    foreach(k_; keys)
    {
        auto k = k_ == "true" ? "on" : k_;
        if (auto n = k in ret)
        {
            ret = *n;
        }
        else
        {
            static if (is(T : void[]))
            {
                return Node((Node[]).init);
            }
            else
            {
                return Node(default_);
            }
        }
    }
    return ret;
}

/// enforceDig
auto edig(Node node, string key, string msg = "")
{
    return edig(node, [key], msg);
}

/// ditto
auto edig(Node node, string[] keys, string msg = "")
{
    Node ret = node;
    foreach(k_; keys)
    {
        auto k = k_ == "true" ? "on" : k_;
        if (auto n = k in ret)
        {
            ret = *n;
        }
        else
        {
            msg = msg.empty ? format!"No such field: %s"(k_) : msg;
            throw new MedalHookException(msg, ret);
        }
    }
    return ret;
}

auto isRegexPattern(string s) @nogc nothrow pure @safe
{
    return s.startsWith("/") && (s.endsWith("/") || s.endsWith("/g"));
}

class MedalHookException : Exception
{
    this(string msg, Node node) nothrow pure
    {
        auto mark = node.startMark;
        super(msg, mark.name, mark.line+1);
        this.column = mark.column+1;
    }

    ulong column;
}

class PreconditionDoesNotHold : Exception
{
    this(string msg, Node node) nothrow pure
    {
        auto mark = node.startMark;
        super(msg, mark.name, mark.line+1);
        this.column = mark.column+1;
    }

    ulong column;
}

auto medalHookEnforce(T)(lazy T exp, string msg, Node node)
{
    auto e = exp();
    if (!e)
    {
        throw new MedalHookException(msg, node);
    }
    return e;
}
