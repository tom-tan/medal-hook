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
        "hook", "Specify ahook file", &hookFiles,
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
    switch(op["type"].get!string)
    {
    case "replace-env":
        auto oldEnv = base["configuration"]["env"].sequence.array;
        auto newEnv = op["env"].sequence.array;
        auto resultedEnv = chain(newEnv, oldEnv).schwartzSort!(`a["name"].get!string`, "a < b", SwapStrategy.stable)
                                                .uniq!`a["name"].get!string == b["name"].get!string`
                                                .array;
        base["configuration"]["env"] = Node(resultedEnv);
        break;
    default:
        break;
    }
    return base;
}
