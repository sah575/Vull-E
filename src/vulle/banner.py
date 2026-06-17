from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text

BANNER = r"""██╗   ██╗██╗   ██╗██╗     ██╗          ███████╗
██║   ██║██║   ██║██║     ██║          ██╔════╝
██║   ██║██║   ██║██║     ██║  █████╗  █████╗
╚██╗ ██╔╝██║   ██║██║     ██║  ╚════╝  ██╔══╝
 ╚████╔╝ ╚██████╔╝███████╗███████╗     ███████╗
  ╚═══╝   ╚═════╝ ╚══════╝╚══════╝     ╚══════╝"""

TAGLINE = "PRE-DEPLOYMENT SECURITY INTELLIGENCE"


def render_banner(console: Console) -> None:
    logo = Text(BANNER, justify="center")
    logo.stylize("bold bright_cyan", 0, 53)
    logo.stylize("bold bright_blue", 54, 107)
    logo.stylize("bold bright_magenta", 108, 160)
    logo.stylize("bold bright_yellow", 161, 214)
    logo.stylize("bold bright_green", 215, len(logo))
    title = Text(
        TAGLINE,
        style="bold bright_white",
        justify="center",
    )
    subtitle = Text(
        "LOCAL-FIRST APPSEC RAG  |  JIRA + CONFLUENCE  |  EVIDENCE-BOUND",
        style="bold cyan",
        justify="center",
    )
    pipeline = Text(justify="center")
    pipeline.append("[ ", style="dim white")
    pipeline.append("JIRA", style="bold bright_blue")
    pipeline.append("+", style="dim white")
    pipeline.append("CONF", style="bold bright_cyan")
    pipeline.append(" ]  =>  [ ", style="dim white")
    pipeline.append("RAG", style="bold bright_magenta")
    pipeline.append(" ]  =>  [ ", style="dim white")
    pipeline.append("RISKS", style="bold bright_yellow")
    pipeline.append(" ]  =>  [ ", style="dim white")
    pipeline.append("TESTS", style="bold bright_green")
    pipeline.append(" ]", style="dim white")
    principles = Text(
        "AUTHORIZED TESTING  |  GUIDANCE-AWARE  |  HUMAN-REVIEWED",
        style="bold bright_white",
        justify="center",
    )
    divider = Text("═" * 72, style="bright_magenta", justify="center")

    console.print(
        Panel(
            Group(
                Align.center(logo),
                divider,
                title,
                subtitle,
                Text(),
                pipeline,
                principles,
            ),
            border_style="bright_magenta",
            padding=(1, 2),
            width=88,
        )
    )
