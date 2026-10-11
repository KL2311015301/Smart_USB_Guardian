from pathlib import Path
import sys
import yara


def get_resource_path(relative_path):
    """
    Return the correct path for project resources.

    Works both when running USB Guardian from Python
    and when running a PyInstaller packaged build.
    """
    if getattr(sys, "frozen", False):
        base_path = Path(sys._MEIPASS)
    else:
        base_path = Path(__file__).resolve().parent.parent

    return base_path / relative_path


RULES_PATH = get_resource_path(
    Path("yara_rules") / "usb_guardian_test.yar"
)

def load_rules():
    """
    Compile and load USB Guardian's YARA rules.
    """
    try:
        rules = yara.compile(filepath=str(RULES_PATH))
        return rules

    except yara.Error as error:
        print("YARA RULE ERROR:", error)
        return None


def scan_file(file_path, rules=None):
    """
    Scan one file using USB Guardian's YARA rules.
    """

    file_path = Path(file_path)

    if not file_path.exists():
        return {
            "success": False,
            "file": str(file_path),
            "matches": [],
            "error": "File does not exist"
        }

    if not file_path.is_file():
        return {
            "success": False,
            "file": str(file_path),
            "matches": [],
            "error": "Path is not a file"
        }

    if rules is None:
        rules = load_rules()

    if rules is None:
        return {
            "success": False,
            "file": str(file_path),
            "matches": [],
            "error": "Could not load YARA rules"
        }

    try:
        # First try YARA's normal filename-based scan.
        matches = rules.match(str(file_path))

        return {
            "success": True,
            "file": str(file_path),
            "matches": [match.rule for match in matches],
            "error": None
        }

    except (yara.Error, OSError) as path_error:
        
        original_path_error = str(path_error)
        
        # -------------------------------------------------
        # Unicode path fallback
        # -------------------------------------------------
        # On Windows, YARA may fail to open some files whose
        # names contain Unicode characters even though Python
        # can access them normally.
        #
        # In that situation, Python reads the file and passes
        # its bytes directly to YARA.
        # -------------------------------------------------
        
        try:
            file_size = file_path.stat().st_size

            # Avoid loading very large files completely into RAM.
            max_fallback_size = 100 * 1024 * 1024  # 100 MB

            if file_size > max_fallback_size:
                return {
                    "success": False,
                    "file": str(file_path),
                    "matches": [],
                    "error": (
                        "YARA could not open file by path and "
                        "Unicode fallback was skipped because "
                        "the file is larger than 100 MB."
                    )
                }

            with file_path.open("rb") as file:
                file_data = file.read()

            matches = rules.match(
                data=file_data
            )

            print(
                "YARA BYTE FALLBACK USED:",
                file_path
            )

            return {
                "success": True,
                "file": str(file_path),
                "matches": [match.rule for match in matches],
                "error": None
            }

        except (yara.Error, OSError) as fallback_error:

            return {
                "success": False,
                "file": str(file_path),
                "matches": [],
                "error": (
                    f"Path scan failed: {original_path_error}; "
                    f"byte fallback failed: {fallback_error}"
                )
            }
        
def scan_directory(directory_path):
    """
    Recursively scan files inside a directory using
    USB Guardian's YARA rules.
    """

    directory_path = Path(directory_path)

    if not directory_path.exists():

        return {
            "success": False,
            "scanned_files": 0,
            "detections": [],
            "errors": [],
            "discovered_files": 0,
            "error_count": 0,
            "error": "Directory does not exist"
        }

    if not directory_path.is_dir():

        return {
            "success": False,
            "scanned_files": 0,
            "detections": [],
            "errors": [],
            "discovered_files": 0,
            "error_count": 0,
            "error": "Path is not a directory"
        }

    detections = []
    errors = []
    
    discovered_files = 0
    scanned_files = 0
    
    # Compile YARA rules once for the entire directory scan.
    rules = load_rules()

    if rules is None:
        return {
            "success": False,
            "scanned_files": 0,
            "detections": [],
            "errors": [],
            "discovered_files": 0,
            "error_count": 0,
            "error": "Could not load YARA rules"
        }

    for file_path in directory_path.rglob("*"):

        if not file_path.is_file():
            continue

        discovered_files += 1

        result = scan_file(
            file_path,
            rules=rules
        )
        
        if result["success"]:
            scanned_files += 1

        if not result["success"]:

            errors.append({
                "file": str(file_path),
                "error": result.get("error")
            })

            continue

        if result["matches"]:

            detections.append({
                "file": str(file_path),
                "matches": result["matches"]
            })

    return {
        "success": True,
        "discovered_files": discovered_files,
        "scanned_files": scanned_files,
        "error_count": len(errors),
        "detections": detections,
        "errors": errors,
        "error": None
    }