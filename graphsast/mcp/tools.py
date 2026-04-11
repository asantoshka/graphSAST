"""In-process MCP tool definitions and executor.

These tools are passed to the LLM as tool_schemas (OpenAI function format).
The executor maps tool names to GraphClient method calls.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

# Fields that bloat token counts without adding security-analysis value
_NODE_NOISE = {"extra", "file_hash", "id"}
_EDGE_NOISE = {"extra", "id"}

if TYPE_CHECKING:
    from graphsast.graph.client import GraphClient


# ── Tool schemas (OpenAI function format) ─────────────────────────────────────

TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "get_function",
            "description": (
                "Get the source code and metadata of a function or method. "
                "Use this to read the actual implementation of a suspicious function."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Function name or qualified name (e.g. 'login' or 'app.views.login')",
                    }
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_callers",
            "description": (
                "Find all functions that call the given function. "
                "Use this to understand where user-controlled data enters a function."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Function name or qualified name to find callers for",
                    }
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_callees",
            "description": (
                "Find all functions called by the given function. "
                "Use this to understand what happens with data inside a function."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Function name or qualified name to find callees for",
                    }
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_nodes",
            "description": (
                "Search for functions, classes, or files by name pattern. "
                "Use this to find related code when you know part of a name."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Name substring to search for (case-insensitive)",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results to return (default 20)",
                        "default": 20,
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Read a source file or a specific line range within it. "
                "Prefer using start_line/end_line to keep context small and focused."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path (absolute or relative to repo root)",
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "First line to read (1-based, inclusive)",
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "Last line to read (1-based, inclusive)",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_file_summary",
            "description": (
                "List all functions, methods, and classes in a file with their line ranges. "
                "Use this to orient yourself in a file before deciding which function to read."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path (absolute or relative to repo root)",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_entry_points",
            "description": (
                "List functions that have no callers — these are likely public API endpoints, "
                "HTTP handlers, or CLI entry points. Use this to understand the attack surface."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "trace_path",
            "description": (
                "Find the call path between two functions using BFS. "
                "Use this to trace how data flows from a source to a sink."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "from_fn": {
                        "type": "string",
                        "description": "Starting function name",
                    },
                    "to_fn": {
                        "type": "string",
                        "description": "Target function name",
                    },
                },
                "required": ["from_fn", "to_fn"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_nodes_by_file",
            "description": (
                "Return all functions, classes, and other nodes in a file with full metadata "
                "(params, return_type, is_test). Richer than get_file_summary."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path (absolute or relative to repo root)",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_edges_for_node",
            "description": (
                "Return all edges (CALLS, IMPORTS_FROM, INHERITS, IMPLEMENTS, CONTAINS) "
                "where the node is source or target. Use this to see the full dependency "
                "picture beyond just call relationships."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "qualified_name": {
                        "type": "string",
                        "description": "Fully qualified name of the node (e.g. 'app.views.login')",
                    }
                },
                "required": ["qualified_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_impact_radius",
            "description": (
                "BFS from one or more files to find all transitively impacted nodes and files. "
                "Use this to assess the blast radius of a vulnerability — which callers, "
                "importers, and subclasses downstream are affected."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file_paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "One or more file paths to start the BFS from",
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum BFS hops (default 4)",
                        "default": 4,
                    },
                },
                "required": ["file_paths"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_flows",
            "description": (
                "Return pre-computed execution flows sorted by criticality. "
                "Each flow traces the call path from an entry point through the codebase. "
                "Use this to quickly find high-criticality paths that touch the vulnerable code. "
                "Returns empty list if flows have not been computed yet."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of flows to return (default 20)",
                        "default": 20,
                    }
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_flow_by_id",
            "description": (
                "Return a single execution flow with its full step-by-step call path "
                "(name, file, line for each hop). Use after get_flows to drill into a specific flow."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "flow_id": {
                        "type": "integer",
                        "description": "Flow ID from get_flows result",
                    }
                },
                "required": ["flow_id"],
            },
        },
    },
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _trim_node(n: dict) -> dict:
    return {k: v for k, v in n.items() if k not in _NODE_NOISE}

def _trim_edge(e: dict) -> dict:
    return {k: v for k, v in e.items() if k not in _EDGE_NOISE}


# ── Executor ──────────────────────────────────────────────────────────────────

def execute_tool(name: str, args: dict, graph: "GraphClient") -> str:
    """Dispatch a tool call to the appropriate GraphClient method."""
    try:
        if name == "get_function":
            fn_name = args.get("name") or args.get("qualified_name", "")
            result = graph.get_function(fn_name)
            if result is None:
                return f"No function found matching '{fn_name}'"
            return json.dumps(_trim_node(result), default=str)

        elif name == "get_callers":
            fn_name = args.get("name") or args.get("qualified_name", "")
            result = graph.get_callers(fn_name)
            if not result:
                return f"No callers found for '{fn_name}'"
            return json.dumps([_trim_node(r) for r in result], default=str)

        elif name == "get_callees":
            fn_name = args.get("name") or args.get("qualified_name", "")
            result = graph.get_callees(fn_name)
            if not result:
                return f"No callees found for '{fn_name}'"
            return json.dumps([_trim_node(r) for r in result], default=str)

        elif name == "search_nodes":
            result = graph.search_nodes(args["pattern"], limit=args.get("limit", 20))
            if not result:
                return f"No nodes found matching '{args['pattern']}'"
            return json.dumps([_trim_node(r) for r in result], default=str)

        elif name == "read_file":
            path = args.get("path") or args.get("file_path", "")
            return graph.read_file(
                path,
                start_line=args.get("start_line"),
                end_line=args.get("end_line"),
            )

        elif name == "get_file_summary":
            path = args.get("path") or args.get("file_path", "")
            result = graph.get_file_summary(path)
            if not result:
                return f"No functions or classes found in '{path}'"
            return json.dumps([_trim_node(r) for r in result], default=str)

        elif name == "list_entry_points":
            result = graph.list_entry_points()
            if not result:
                return "No entry points found (all functions have callers)"
            return json.dumps([_trim_node(r) for r in result], default=str)

        elif name == "trace_path":
            path = graph.trace_path(args["from_fn"], args["to_fn"])
            if not path:
                return f"No call path found from '{args['from_fn']}' to '{args['to_fn']}'"
            return " → ".join(path)

        elif name == "get_nodes_by_file":
            path = args.get("path") or args.get("file_path", "")
            result = graph.get_nodes_by_file(path)
            if not result:
                return f"No nodes found in '{path}'"
            return json.dumps([_trim_node(r) for r in result], default=str)

        elif name == "get_edges_for_node":
            qname = args.get("qualified_name") or args.get("name", "")
            result = graph.get_edges_for_node(qname)
            if not result:
                return f"No edges found for '{qname}'"
            return json.dumps([_trim_edge(r) for r in result], default=str)

        elif name == "get_impact_radius":
            result = graph.get_impact_radius(
                args["file_paths"],
                max_depth=args.get("max_depth", 4),
            )
            return json.dumps(result, default=str)

        elif name == "get_flows":
            result = graph.get_flows(limit=args.get("limit", 20))
            if not result:
                return "No flows available. Flows are computed during graph build."
            return json.dumps(result, default=str)

        elif name == "get_flow_by_id":
            result = graph.get_flow_by_id(args["flow_id"])
            if result is None:
                return f"No flow found with id {args['flow_id']}"
            return json.dumps(result, default=str)

        else:
            return f"Unknown tool: {name}"

    except Exception as exc:
        return f"Tool error ({name}): {exc}"
