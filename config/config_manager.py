import json
import shutil
import sys
from pathlib import Path


def get_default_config_path():
    """
    Return the settings file included with USB Guardian.

    Works in both normal Python development mode
    and PyInstaller packaged mode.
    """

    if getattr(sys, "frozen", False):
        base_path = Path(sys._MEIPASS)
    else:
        base_path = Path(__file__).resolve().parent.parent

    return base_path / "config" / "settings.json"


def get_user_config_path():
    """
    Return the persistent writable settings location.
    """

    user_folder = (
        Path.home()
        / "USBGuardian"
        / "config"
    )

    user_folder.mkdir(
        parents=True,
        exist_ok=True
    )

    return user_folder / "settings.json"


DEFAULT_CONFIG_FILE = get_default_config_path()
CONFIG_FILE = get_user_config_path()


def ensure_user_config():
    """
    Create the user's persistent settings file
    the first time USB Guardian runs.
    """

    if CONFIG_FILE.exists():
        return

    if DEFAULT_CONFIG_FILE.exists():

        shutil.copy2(
            DEFAULT_CONFIG_FILE,
            CONFIG_FILE
        )

    else:

        default_settings = {
            "scan_mode": "test",
            "auto_scan": False,
            "notifications": True,
            "antivirus_engine": "Microsoft Defender"
        }

        with open(
            CONFIG_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                default_settings,
                file,
                indent=4
            )


def load_settings():

    ensure_user_config()

    try:

        with open(
            CONFIG_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except (
        OSError,
        json.JSONDecodeError
    ):

        return {
            "scan_mode": "test",
            "auto_scan": False,
            "notifications": True,
            "antivirus_engine": "Microsoft Defender"
        }


def save_settings(settings):

    CONFIG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        CONFIG_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            settings,
            file,
            indent=4
        )