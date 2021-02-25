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
    auto hs = hooks.sequence.find!(h => h["target"].get!string == app);
    if (hs.empty) return base;
    auto h = hs.front;
    auto result = h["operations"].sequence.fold!applyOperation(base);
    return result;
}

auto applyOperation(ref Node base, Node op)
{
    auto type = op["type"].get!string;
    switch(type)
    {
    case "replace-env":
        enforce(base["type"] == "network");
        auto oldEnv = base["configuration"]["env"].sequence.array;
        auto newEnv = op["env"].sequence.array;
        auto resultedEnv = chain(newEnv, oldEnv).schwartzSort!(`a["name"].get!string`, "a < b", SwapStrategy.stable)
                                                .uniq!`a["name"].get!string == b["name"].get!string`
                                                .array;
        base["configuration"]["env"] = Node(resultedEnv);
        break;
    case "add-transitions":
        enforce(base["type"] == "network");
        if (auto trs = "transitions" in op)
        {
            auto curTrs = "transitions" in base ? base["transitions"].sequence.array : [];
            auto newTrs = trs.sequence.array;
            base["transitions"] = Node(curTrs~newTrs);
        }
        if (auto on = true in op)
        {
            if (auto bon_ = true in base)
            {
                auto bon = *bon_;
                if (auto suc = "success" in *on)
                {
                    auto curTrs = "success" in bon ? bon["success"].sequence.array : [];
                    auto newTrs = suc.sequence.array;
                    bon["success"] = Node(curTrs~newTrs);
                }
                if (auto fail = "failure" in *on)
                {
                    auto curTrs = "failure" in bon ? bon["failure"].sequence.array : [];
                    auto newTrs = fail.sequence.array;
                    bon["failure"] = Node(curTrs~newTrs);
                }
                if (auto ex = "exit" in *on)
                {
                    auto curTrs = "exit" in bon ? bon["exit"].sequence.array : [];
                    auto newTrs = ex.sequence.array;
                    bon["exit"] = Node(curTrs~newTrs);
                }
            }
            else
            {
                base[true] = *on;
            }
        }
        break;
    case "add-out":
        enforce(base["type"] == "network");
        if (base["name"] == op["target"])
        {
            auto current = base["out"].sequence.array;
            auto added = op["out"].sequence.array;
            // TODO: should not be overwrapped
            base["out"] = Node(current~added);
        }
        else
        {
            auto rng = base["transitions"].sequence
                                          .find!(t => t["name"] == op["target"]);
            if (rng.empty)
            {
                throw new Exception("No such transition: "~op["target"].get!string);
            }
            // limitation: does not support to add them to `on` transitions
            auto current = rng.front["out"].sequence.array;
            auto added = op["out"].sequence.array;
            rng.front["out"] = Node(current~added);
        }
        break;
    case "insert-before":
        break;
    default:
        throw new Exception("Unsupported hook type: "~type);
    }
    return base;
}
