import argparse
import importlib
import importlib.util
from pathlib import Path
from types import ModuleType
import hashlib
import sys
import ast
import logging
from typing import DefaultDict, List

from nest_client.client import AsyncNestClient, NestClient
from nest_client.config import DEFAULT_URL
from nest_client.mutators.descriptor_runner import run_descriptor_file
from nest_client.scenario import Scenario, ValidationResult
from nest_client.sequence import Event
from nest_client.time import s


# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

def configure_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

# ------------------------------------------------------------
# Utilities
# ------------------------------------------------------------

class Color:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

def green(text): return f"{Color.GREEN}{text}{Color.RESET}"
def red(text): return f"{Color.RED}{text}{Color.RESET}"


_loaded_modules: dict[Path, ModuleType] = {}


def load_module_from_path(file_path: Path) -> ModuleType:
    file_path = file_path.resolve()

    if file_path in _loaded_modules:
        return _loaded_modules[file_path]

    # Stable unique name
    module_name = "_scenario_" + hashlib.md5(
        str(file_path).encode()
    ).hexdigest()

    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module from {file_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    _loaded_modules[file_path] = module
    return module


def file_has_scenario_decorator(file_path: Path) -> bool:
    """
    Quickly check if a .py file uses @scenario without executing it.
    """
    try:
        tree = ast.parse(file_path.read_text(encoding="utf-8"))
    except SyntaxError:
        return False

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            # Matches @scenario(...) 
            if isinstance(decorator, ast.Call):
                func = decorator.func
                name = func.id if isinstance(func, ast.Name) else (
                    func.attr if isinstance(func, ast.Attribute) else None
                )
                if name == "scenario":
                    return True
            # Matches bare @scenario (no-arg form)
            elif isinstance(decorator, ast.Name) and decorator.id == "scenario":
                return True
    return False


def load_scenario(path_spec: str) -> Scenario:
    """
    Load scenario from "path/to/file.py:scenario_name"
    """
    try:
        file_part, scenario_name = path_spec.split(":")
    except ValueError:
        raise ValueError(
            "Scenario must be specified as path/to/file.py:scenario_name"
        )

    file_path = Path(file_part).resolve()

    module = load_module_from_path(file_path)

    obj = getattr(module, scenario_name, None)

    if not isinstance(obj, Scenario):
        raise ValueError(f"{scenario_name} is not a Scenario in {file_part}")

    return obj


def discover_scenarios(dir_path: str):
    """
    Recursively discover @scenario functions inside a folder.
    """
    results = []
    path = Path(dir_path)

    for file in path.rglob("*.py"):
        if "__pycache__" in file.parts:
            continue

        if not file_has_scenario_decorator(file):
            continue

        try:
            module = load_module_from_path(file)
        except Exception as _:
            continue

        for attr in dir(module):
            obj = getattr(module, attr)
            if isinstance(obj, Scenario):
                results.append(f"{file.as_posix()}:{attr}")

    return sorted(results)


def print_validation_report(scenario: Scenario, results: List[ValidationResult]):
    REPORT_WIDTH = 80
    print()
    print(f"Scenario: {scenario.name}")
    print()

    total_pass = 0
    scope_groups = DefaultDict(list)
    
    for result in results:
        path = tuple(scope.label or '' for scope in result.op.scope_stack)
        scope_groups[path].append(result)
    
    sorted_paths = sorted(scope_groups.keys())
    
    for path in sorted_paths:
        scope_results = scope_groups[path]
        scope = scope_results[0].op.scope_stack[-1]
        path_string = " / ".join([label for label in path if label != ''])

        print("─" * REPORT_WIDTH)
        scope_window = f"[{scope.start.as_unit(s)}s -> {scope.end.as_unit(s)}s]"
        print(f"{path_string:<{REPORT_WIDTH - len(scope_window) - 1}} {scope_window}")
        print("─" * REPORT_WIDTH)
        print()

        for result in scope_results:
            event = result.op.item
            assert isinstance(event, Event)

            expect = "EXPECT" if event.expect else "FORBID"
            symbol = green('OK') if result.success else red('FAILED')
            window_start = result.op.offset.as_unit(s)
            window_end = (result.op.offset + event.within if event.within else scope.end).as_unit(s)
            event_window = f"[{window_start}s -> {window_end}s]"

            print(f"  [{symbol}] {expect} {event.component}.{event.name} {event_window}")
            total_pass += result.success

        print()

    total_fail = len(results) - total_pass

    print("─" * REPORT_WIDTH)
    print("Summary:")
    if total_pass > 0:
        print(f"  {green(str(total_pass) + ' passed')}")
    else:
        print(f"  {total_pass} passed")
    if total_fail > 0:
        print(f"  {red(str(total_fail) + ' failed')}")
    else:
        print(f"  {total_fail} failed")
    print()

    if total_fail == 0:
        print(green("Result: SUCCESS"))
    else:
        print(red("Result: FAILED"))


# ------------------------------------------------------------
# Interactive shell
# ------------------------------------------------------------

def interactive_shell(args):
    client = NestClient(args.url)
    connected = False

    print("NEST Interactive Shell — type 'help' for options.\n")

    def print_help():
        print("""
Available commands:
  connect
  disconnect
  upload <file>
  start
  stop
  quit / exit
  help
""")

    while True:
        try:
            cmd = input("> ").strip().split()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting shell...")
            break

        if not cmd:
            continue

        match cmd[0]:
            case "help":
                print_help()

            case "connect":
                if connected:
                    print("Already connected.")
                else:
                    client.connect()
                    connected = True
                    print("Connected.")

            case "disconnect":
                if connected:
                    client.disconnect()
                    connected = False
                    print("Disconnected.")
                else:
                    print("Not connected.")

            case "upload":
                if len(cmd) < 2:
                    print("Usage: upload <file>")
                    continue
                client.load_topology_from_file(cmd[1])
                print("Uploaded.")

            case "start":
                client.start()
                print("Started.")

            case "stop":
                client.stop()
                print("Stopped.")

            case "quit" | "exit":
                if connected:
                    client.disconnect()
                print("Goodbye.")
                break

            case _:
                print("Unknown command. Type 'help'.")


# ------------------------------------------------------------
# Subcommands
# ------------------------------------------------------------

def run_scenario(args):
    scenario = load_scenario(args.scenario)

    print(f"Running scenario {scenario.name}")
    client = AsyncNestClient(args.url)
    results = scenario.run(client)
    print_validation_report(scenario, results)


def run_mutator(args):
    scenario, results, url, scenario_seed, artifacts_dir = run_descriptor_file(args.descriptor, args.url)

    print(f"Running scenario {scenario.name}")
    print(f"Descriptor: {args.descriptor}")
    print(f"Server URL: {url}")
    if scenario_seed is not None:
        print(f"Scenario mutation seed: {scenario_seed}")
    print(f"Saved run artifacts to: {artifacts_dir}")

    print_validation_report(scenario, results)



def show_scenario(args):
    scenario = load_scenario(args.scenario)

    print(f"Scenario: {scenario.name} (duration: {scenario.sequence.duration()})")
    for op in scenario.sequence.flatten():
        print(op)


def list_scenarios(args):
    scenarios = discover_scenarios(args.package)

    if not scenarios:
        print("No scenarios found.")
        return

    for s in scenarios:
        print(s)


# ------------------------------------------------------------
# CLI args parser
# ------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nest-client")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--url", help=f"Websocket URL [default={DEFAULT_URL}]", default=DEFAULT_URL)

    subparsers = parser.add_subparsers(dest="command")

    # run
    run_parser = subparsers.add_parser("run", help="Run a scenario")
    run_parser.add_argument("scenario", help="path/to/file.py:scenario_name")
    run_parser.set_defaults(func=run_scenario)

    # run-mutator
    descriptor_parser = subparsers.add_parser(
        "run-mutator",
        help="Run scenario/topology mutation workflow from a descriptor YAML file",
    )
    descriptor_parser.add_argument("descriptor", help="Path to descriptor YAML file")
    descriptor_parser.set_defaults(func=run_mutator)

    # show
    show_parser = subparsers.add_parser("show", help="Show scenario timeline")
    show_parser.add_argument("scenario", help="path/to/file.py:scenario_name")
    show_parser.set_defaults(func=show_scenario)

    # list
    list_parser = subparsers.add_parser("list", help="List scenarios in package")
    list_parser.add_argument("package", help="Package to scan")
    list_parser.set_defaults(func=list_scenarios)

    return parser


# ------------------------------------------------------------
# Main entry
# ------------------------------------------------------------

def main():
    parser = build_parser()
    args = parser.parse_args()

    configure_logging(args.verbose)

    if args.command is None:
        interactive_shell(args)
        return

    try:
        # No subcommand -> interactive shell
        if args.command is None:
            interactive_shell(args)
        else:
            args.func(args)

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)

    except Exception as e:
        from nest_client.exceptions import NestError
        if isinstance(e, NestError):
            # WS drop mid-scenario (NEST server restart, QEMU crash, etc.)
            print(f"\nNEST connection lost: {e}", file=sys.stderr)
            print("The NEST server may have crashed or restarted. Check nest_server.log.", file=sys.stderr)
            sys.exit(1)
        # Unexpected error
        if args.debug:
            raise  # full traceback
        else:
            print("Unexpected error occurred.", file=sys.stderr)
            print(f"{type(e).__name__}: {e}", file=sys.stderr)
            sys.exit(1)

