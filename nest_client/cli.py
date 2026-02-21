import argparse
import importlib
import pkgutil
import sys
import logging
from typing import DefaultDict, List

from nest_client.client import AsyncNestClient, NestClient
from nest_client.config import DEFAULT_URL
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

def load_scenario(dotted_path: str) -> Scenario:
    """
    Load scenario from dotted path
    """
    try:
        module_path, scenario_name = dotted_path.rsplit(".", 1)
    except ValueError:
        raise ValueError(
            "Scenario must be specified as module.function "
            "(e.g. scenarios.temperature.raise_temperature)"
        )

    module = importlib.import_module(module_path)
    obj = getattr(module, scenario_name)

    if not isinstance(obj, Scenario):
        raise ValueError("Target is not a scenario.")

    return obj


def discover_scenarios(package_name: str):
    """
    Recursively discover @scenario functions inside a package.
    """
    package = importlib.import_module(package_name)
    results = []

    for _, modname, ispkg in pkgutil.walk_packages(
        package.__path__,
        package.__name__ + "."
    ):
        if ispkg:
            continue

        module = importlib.import_module(modname)

        for attr in dir(module):
            obj = getattr(module, attr)
            if isinstance(obj, Scenario):
                results.append(f"{modname}.{attr}")

    return sorted(results)


def print_validation_report(scenario: Scenario, results: List[ValidationResult]):
    REPORT_WIDTH = 80
    print()
    print(f"Scenario: {scenario.name}")
    print()

    total_pass = 0
    scope_groups = DefaultDict(list)
    
    for result in results:
        path = tuple(scope.label for scope in result.op.scope_stack)
        scope_groups[path].append(result)
    
    sorted_paths = sorted(scope_groups.keys())
    
    for path in sorted_paths:
        scope_results = scope_groups[path]
        scope = scope_results[0].op.scope_stack[-1]
        path_string = " / ".join([label or '<anonymous>' for label in path])

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
    parser.add_argument("--url", help=f"Websocket URL [default={DEFAULT_URL}]", default=DEFAULT_URL)

    subparsers = parser.add_subparsers(dest="command")

    # run
    run_parser = subparsers.add_parser("run", help="Run a scenario")
    run_parser.add_argument("scenario", help="module.function")
    run_parser.set_defaults(func=run_scenario)

    # show
    show_parser = subparsers.add_parser("show", help="Show scenario timeline")
    show_parser.add_argument("scenario", help="module.function")
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
        # Unexpected error
        print("Unexpected error occurred.", file=sys.stderr)
        print(f"{type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)

