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

    auto appliedNetwork = hookFiles.map!(f => Loader.fromFile(f).load).fold!apply(net);
    auto app = appender!string;
    dumper.dump(app, appliedNetwork);
    writeln(app[]);
    return 0;
}

auto apply(ref Node base, Node hook)
{
    auto app = enforce("application" in base).get!string;
    auto hooks = enforce("hooks" in hook);
    auto hs = hooks.sequence.filter!(h => h["target"].get!string == app);
    if (hs.empty) return base;
    auto h = hs.front;
    auto result = h["operations"].sequence.fold!applyOperation(base);
    if (auto ah = "applied-hooks" in result)
    {
        ah.add(hook["id"]);
    }
    else
    {
        result.add("applied-hooks", Node([hook["id"]]));
    }
    return result;
}

Node applyOperation(Node base, Node op)
{
    auto type = op["type"].get!string;
    switch(type)
    {
    case "replace-env":
        enforce(base["type"] == "network");
        auto newEnv = op["env"].sequence
                               .map!(e => tuple(e["name"].get!string,
                                                e["value"].get!string))
                               .assocArray;
        auto replacedEnv =
            base["configuration"]["env"]
                .sequence
                .map!((e) {
                    auto name = e["name"].get!string;
                    auto oldValue = e["value"].get!string;
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
        enforce(base["type"] == "network");
        auto target = op["target"].get!string;
        auto rng = base["transitions"].sequence
                                      .enumerate
                                      .find!(t => t.value["name"] == target);
        enforce(!rng.empty, "No such transition: "~target);
        base["transitions"][rng.front.index] = op["transition"];
        base["transitions"][rng.front.index]["name"] = target;
        return base;
    case "add-transitions":
        enforce(base["type"] == "network");
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
        enforce(base["type"] == "network");
        auto target = op["target"].get!string;
        if (target.isRegexPattern)
        {
            enforce(!target.endsWith("g"));
            auto expandPattern(Node baseOp, Captures!string c)
            {
                Node ret;
                ret.add("type", Node("add-out"));
                ret["target"] = Node(c.hit);
                auto cap = c[1];
                ret["out"] = Node(baseOp["out"].sequence
                                           .map!((o) {
                                               Node newOut;
                                               newOut.add("place", o["place"]);
                                               newOut["port-to"] = o["port-to"].get!string.replace("~1", cap);
                                               return newOut;
                                           })
                                           .array);
                return ret;
            }
            auto re = regex(target[1..$-1]);
            auto trs = base["transitions"].sequence;
            foreach(t; trs.filter!(t => t["name"].get!string.matchFirst(re)))
            {
                auto cap = t["name"].get!string.matchFirst(re);
                auto expandedOp = expandPattern(op, cap);
                base = applyOperation(base, expandedOp);
            }
        }
        else if (base["name"] == target)
        {
            auto current = base["out"].sequence.array;
            auto added = op["out"].sequence.array;
            // TODO: should not be overwrapped
            base["out"] = Node(current~added);
        }
        else
        {
            // limitation: does not support to add them to `on` transitions
            auto rng = base["transitions"].sequence
                                          .filter!(t => t["name"] == target);
            enforce(!rng.empty, "No such transition: "~target);
            auto current = rng.front["out"].sequence.array;
            auto added = op["out"].sequence.array;
            rng.front["out"] = Node(current~added);
        }
        return base;
    case "insert-before":
        enforce(base["type"] == "network");
        auto trs = base["transitions"];
        auto rng = trs.sequence
                      .filter!(t => t["name"] == op["target"]);
        enforce(!rng.empty, "No such transition: "~op["target"].get!string);
        auto target = rng.front;
        auto replaceMap = op["in"].sequence
                                  .map!(pair => tuple(pair["replaced"].get!string,
                                                      pair["with"].get!string))
                                  .assocArray;
        target["in"] = Node(target["in"]
                                .sequence
                                .map!((p) {
                                    Node n;
                                    auto pl = p["place"].get!string;
                                    n.add("place", replaceMap.get(pl, pl));
                                    n.add("pattern", p["pattern"]);
                                    return n;
                                })
                                .array);
        static replaceRef(string s, string from, string to)
        {
            return s.replace(format!"~(%s)"(from), format!"~(%s)"(to));
        }
        if (target["type"] == "shell")
        {
            target["command"] = target["command"]
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
                                      n.add("place", p["place"]);
                                      auto pat = p["pattern"].get!string;
                                      auto newPat =
                                         pat.matchAll(ctRegex!`~\((.+)\)`)
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
        auto inserted = op["transitions"].sequence.array;
        base["transitions"] = Node(curTrs~inserted);
        return base;
    default:
        throw new Exception("Unsupported hook type: "~type);
    }
    assert(false);
}

Node[] expandTransition(Node node, Node base)
{
    enforce(base["type"] == "network");
    if (node["type"] != "shell")
    {
        return [node];
    }

    Node[] nonExpandedIn;
    Node[] expandedIn;
    auto isExpandPattern = false;
    auto isGlobalPattern = false;
    Captures!string[] caps;
    foreach(inp; node["in"].sequence)
    {
        auto pl = inp["place"].get!string;
        if (pl.isRegexPattern)
        {
            enforce(!isExpandPattern, "Only one regex pattern is allowed");
            isExpandPattern = true;
            isGlobalPattern = pl.endsWith("g");
            auto end = isGlobalPattern ? pl.length-2 : pl.length-1;
            auto re = regex(pl[1..end]);
            enumeratePlaces(base)
                .filter!(p => p.matchFirst(re))
                .each!((p) {
                    Node n;
                    n.add("place", p);
                    n.add("pattern", inp["pattern"]);
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
        auto pls = expandedIn.map!(i => format!"~(%s)"(i["place"].get!string))
                             .array;
        auto cmd = node["command"].get!string.replace("~@", pls.joiner(" ").array);
        Node ret;
        ret.add("name", node["name"]);
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
            auto name = node["name"].get!string;
            pats.each!(p => name = name.replace(p[0], p[1]));
            ret.add("name", name);

            ret.add("type", "shell");
            ret.add("in", nonExpandedIn~expandedIn[idx]);


            auto cmd = node["command"].get!string;
            pats.each!(p => cmd = cmd.replace(p[0], p[1]));
            ret.add("command", cmd);

            if (auto o = "out" in node)
            {
                auto newOut = o.sequence.map!((oo) {
                    Node out_;
                    auto pl = oo["place"].get!string;
                    pats.each!(p => pl = pl.replace(p[0], p[1]));
                    out_.add("place", pl);
                    out_.add("pattern", oo["pattern"]);
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
    enforce(n["type"] == "network");
    return chain(n.dig(["transitions"],   []).sequence,
                 n.dig(["on", "success"], []).sequence,
                 n.dig(["on", "failure"], []).sequence,
                 n.dig(["on", "exit"],    []).sequence).array;
}

auto enumeratePlaces(Node node)
{
    auto places(Node n)
    {
        if (n["type"] == "invocation")
        {
            auto inp = n.dig(["in"], [])
                        .sequence
                        .map!(n => n["place"].get!string)
                        .array;
            auto outs = n.dig(["out"], [])
                         .sequence
                         .map!(n => n["port-to"].get!string)
                         .array;
            return inp~outs;

        }
        else
        {
            return chain(n.dig(["in"], []).sequence,
                         n.dig(["out"], []).sequence)
                    .map!(n => n["place"].get!string)
                    .array;
        }
    }
    auto arr =  enumerateTransitions(node)
                    .map!(n => places(n))
                    .joiner
                    .array;
    return arr.sort.uniq.array;
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

auto isRegexPattern(string s) @nogc nothrow pure @safe
{
    return s.startsWith("/") && (s.endsWith("/") || s.endsWith("/g"));
}