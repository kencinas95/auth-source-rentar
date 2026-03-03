from jinja2 import Environment, FileSystemLoader, select_autoescape

__environment__: Environment | None = None

from backend.config.settings import DATA_ROOT


def init():
    global __environment__

    if not __environment__:
        __environment__ = Environment(loader=FileSystemLoader(DATA_ROOT / "emails"),
                                      autoescape=select_autoescape(["html", "xml"]), )


def environment():
    global __environment__

    if not __environment__:
        raise ValueError("Jinja2 Environment not initialized")

    return __environment__


def render(name: str, **context) -> str:
    template = environment().get_template(name)
    return template.render(context)
