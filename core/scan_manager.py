import time
from pathlib import Path

from scanner.defender import (
    scan_path,
    get_defender_detections,
    extract_detected_files,
    get_new_defender_detections,
    get_drive_detections_since
)

from scanner.hasher import calculate_sha256
from scanner.yara_scanner import scan_directory

from database.database import save_scan
from config.config_manager import load_settings
from quarantine.quarantine_manager import quarantine_file


def scan_usb(drive, usb_connected_time):

    drive_letter = drive["DriveLetter"]
    drive_path = f"{drive_letter}:\\"

    settings = load_settings()

    print("Loaded settings:", settings)

    # -----------------------------------------
    # Determine scan target
    # -----------------------------------------

    if settings.get("scan_mode") == "test":

        scan_target = f"{drive_letter}:\\USBGuardian_Test"

    elif settings.get("scan_mode") == "full":

        scan_target = drive_path

    else:

        scan_target = drive_path

    print("DRIVE PATH:", drive_path)
    print("SCAN TARGET BEFORE DEFENDER:", scan_target)


    # -----------------------------------------
    # Calculate hashes BEFORE Defender scan
    # -----------------------------------------

    file_hashes = {}

    scan_target_path = Path(scan_target)

    if (
        settings.get("scan_mode") == "test"
        and scan_target_path.exists()
    ):

        if scan_target_path.is_file():

            files_to_hash = [scan_target_path]

        else:

            files_to_hash = [
                file
                for file in scan_target_path.rglob("*")
                if file.is_file()
            ]

        print(
            "Files found for hashing:",
            len(files_to_hash)
        )

        for file_path in files_to_hash:

            try:

                hash_value = calculate_sha256(
                    file_path
                )

                if hash_value:

                    normalized_path = str(
                        file_path
                    ).lower()

                    file_hashes[
                        normalized_path
                    ] = hash_value

                    print(
                        "HASH:",
                        file_path,
                        hash_value
                    )

            except Exception as e:

                print(
                    "HASH ERROR:",
                    e
                )

    else:

        if settings.get("scan_mode") == "full":

            print("FULL SCAN MODE")
            print("Full scan target:", scan_target)
            print("Pre-scan hashing skipped for full USB scan.")

        else:

            print(
                "Scan target does not exist:",
                scan_target
            )

    # -----------------------------------------
    # Run Microsoft Defender
    # -----------------------------------------


    # -----------------------------------------
    # Get Defender detections BEFORE scan
    # -----------------------------------------

    before_detections = get_defender_detections()

    print(
        "DEFENDER DETECTIONS BEFORE SCAN:",
        before_detections
    )

    scan_start = time.time()

    result = scan_path(scan_target)


    # -----------------------------------------
    # Get Defender detections AFTER scan
    # -----------------------------------------

    after_detections = get_defender_detections()

    print(
        "DEFENDER DETECTIONS AFTER SCAN:",
        after_detections
    )
    
    # -----------------------------------------
    # Check recent real-time Defender detections
    # for the current USB drive
    # -----------------------------------------

    print(
        "USB CONNECTION TIME USED FOR SCAN:",
        usb_connected_time
    )

    recent_drive_detections = get_drive_detections_since(
        after_detections,
        drive_letter,
        usb_connected_time
    )

    print(
        "RECENT USB DEFENDER DETECTIONS:",
        recent_drive_detections
    )



    # -----------------------------------------
    # Run YARA scan
    # -----------------------------------------

    print("Starting YARA scan:", scan_target)

    yara_result = {
        "success": False,
        "scanned_files": 0,
        "detections": [],
        "errors": [],
        "error": None
    }

    if scan_target_path.exists():

        if scan_target_path.is_dir():

            yara_result = scan_directory(
                scan_target
            )

        else:

            print(
                "YARA directory scan skipped:",
                scan_target
            )

    print(
        "YARA SCAN RESULT:",
        yara_result
    )
    
    yara_discovered_files = yara_result.get("discovered_files", 0)
    yara_scanned_files = yara_result.get("scanned_files", 0)
    yara_error_count = yara_result.get("error_count", 0)

    print("YARA FILES DISCOVERED:", yara_discovered_files)
    print("YARA FILES SCANNED:", yara_scanned_files)
    print("YARA SCAN ERRORS:", yara_error_count)
    
    # -----------------------------------------
    # Calculate total security scan duration
    # Defender + YARA
    # -----------------------------------------

    scan_end = time.time()

    scan_duration = round(
        scan_end - scan_start,
        2
    )

    print(
        "TOTAL SCAN DURATION:",
        scan_duration,
        "seconds"
    )

    # -----------------------------------------
    # SAFE
    # -----------------------------------------

    if (
        result["status"] == "SAFE"
        and not recent_drive_detections
        and not yara_result["detections"]
    ):

        save_scan(
            drive["DiskName"],
            drive_path,
            scan_target,
            "SAFE",
            0,
            scan_duration,
            detected_files=[],
            sha256=None,
            threat_ids=[],
            remediation_status="NONE",
            detection_engine="Microsoft Defender + YARA",
            yara_rules=[]
        )

        return {
            "device": drive["DiskName"],
            "drive": drive_path,
            "scan_path": scan_target,
            "status": "SAFE",
            "threats": 0,
            "detected_files": [],
            "sha256": None,
            "threat_ids": [],
            "remediation_status": "NONE",
            "detection_engine": "Microsoft Defender + YARA",
            "yara_rules": [],
            "files_discovered": yara_discovered_files,
            "files_scanned": yara_scanned_files,
            "scan_errors": yara_error_count,
            "duration": scan_duration
        }
        

    # -----------------------------------------
    # THREAT DETECTED
    # -----------------------------------------

    if (
        result["status"] == "THREAT_DETECTED"
        or recent_drive_detections
        or yara_result["detections"]
    ):

        # -------------------------------------
        # Keep only detections created by
        # this scan
        # -------------------------------------

        if recent_drive_detections:

            print(
                "Using recent real-time Defender detection."
            )

            detections = recent_drive_detections

        else:

            detections = get_new_defender_detections(
                before_detections,
                after_detections
            )


        print(
            "NEW DEFENDER DETECTIONS:",
            detections
        )

        # If Defender reports a threat but no new detection
        # record was created, check existing Defender records
        # for files belonging to the current scan target.
        if not detections and result["status"] == "THREAT_DETECTED":

            print(
                "No new Defender record found."
            )

            print(
                "Checking existing detections for current scan target..."
            )

            scan_target_normalized = (
                str(scan_target)
                .lower()
                .rstrip("\\")
            )

            matching_detections = []

            for detection in after_detections:

                resources = detection.get(
                    "Resources",
                    []
                )

                if isinstance(resources, str):
                    resources = [resources]

                for resource in resources:

                    resource_normalized = (
                        str(resource).lower()
                    )

                    if scan_target_normalized in resource_normalized:

                        matching_detections.append(
                            detection
                        )

                        break
            # Defender normally returns the most recent
            # detections first. When no new record was
            # created by the manual scan, use only the
            # most recent matching detection instead of
            # reporting all historical detections.

            if matching_detections:
                
                detections = [
                    matching_detections[0]
                ]
            
            else:
                
                detections = []
                
            print(
                "FALLBACK DEFENDER DETECTION:",
                detections
            )
            

        
        detected_files = extract_detected_files(
            detections
        )

        # -------------------------------------
        # Add YARA detected files
        # -------------------------------------

        yara_detected_files = []
        yara_matches = []

        for yara_detection in yara_result["detections"]:

            yara_file = yara_detection.get("file")

            if yara_file:
                yara_detected_files.append(yara_file)

                if yara_file not in detected_files:
                    detected_files.append(yara_file)

            for rule_name in yara_detection.get("matches", []):

                if rule_name not in yara_matches:
                    yara_matches.append(rule_name)

        if yara_detected_files:
            print(
                "YARA DETECTED FILES:",
                yara_detected_files
            )

            print(
                "YARA MATCHED RULES:",
                yara_matches
            )


        # -------------------------------------
        # Determine detection engine
        # -------------------------------------

        defender_detected = bool(detections)
        yara_detected = bool(yara_matches)

        if defender_detected and yara_detected:
            detection_engine = "Microsoft Defender + YARA"

        elif defender_detected:
            detection_engine = "Microsoft Defender"

        elif yara_detected:
            detection_engine = "YARA"

        else:
            detection_engine = "Unknown"

        print("DETECTION ENGINE:", detection_engine)
        print("YARA RULES:", yara_matches)
        
        # -------------------------------------
        # Quarantine / remediation handling
        # -------------------------------------

        remediation_status = "NONE"

        for detected_file in detected_files:

            detected_path = Path(
                detected_file
            )

            if detected_path.exists():

                print(
                    "Detected file still exists."
                )

                # Hash detected file before quarantine
                normalized_detected_file = str(
                    detected_file
                ).lower()

                if normalized_detected_file not in file_hashes:

                    try:

                        hash_value = calculate_sha256(
                            detected_file
                        )

                        if hash_value:

                            file_hashes[
                                normalized_detected_file
                            ] = hash_value

                            print(
                                "DETECTED FILE HASH:",
                                detected_file,
                                hash_value
                            )

                    except Exception as error:

                        print(
                            "Could not hash detected file:",
                            detected_file,
                            error
                        )

                print(
                    "Attempting USB Guardian quarantine:",
                    detected_file
                )

                quarantine_result = quarantine_file(
                    detected_file
                )

                print(
                    "QUARANTINE RESULT:",
                    quarantine_result
                )

                if quarantine_result.get("success"):

                    remediation_status = (
                        "QUARANTINED_BY_USB_GUARDIAN"
                    )

                else:

                    remediation_status = (
                        "QUARANTINE_FAILED"
                    )

            else:

                print(
                    "Detected file no longer exists:",
                    detected_file
                )

                print(
                    "Assuming Microsoft Defender "
                    "already remediated the threat."
                )

                remediation_status = (
                    "REMEDIATED_BY_DEFENDER"
                )

        threat_ids = []

        for detection in detections:

            threat_id = detection.get(
                "ThreatID"
            )

            if threat_id is not None:

                if threat_id not in threat_ids:

                    threat_ids.append(
                        threat_id
                    )

        # -------------------------------------
        # Match detected files to stored hash
        # -------------------------------------

        detected_hashes = {}

        for detected_file in detected_files:

            normalized_detected_file = (
                str(detected_file).lower()
            )

            hash_value = file_hashes.get(
                normalized_detected_file
            )

            if hash_value:

                detected_hashes[
                    detected_file
                ] = hash_value

                print(
                    "MATCHED HASH:",
                    detected_file,
                    hash_value
                )

            else:

                print(
                    "No hash available for detected file:",
                    detected_file
                )

        # -------------------------------------
        # First detected file hash for now
        # -------------------------------------

        sha256 = None

        if detected_hashes:

            sha256 = next(
                iter(
                    detected_hashes.values()
                )
            )

        # -------------------------------------
        # Save scan
        # -------------------------------------

        save_scan(
            drive["DiskName"],
            drive_path,
            scan_target,
            "UNSAFE",
            len(detected_files) or 1,
            scan_duration,
            detected_files=detected_files,
            sha256=sha256,
            threat_ids=threat_ids,
            remediation_status=remediation_status,
            detection_engine=detection_engine,
            yara_rules=yara_matches
        )

        return {
            "device": drive["DiskName"],
            "drive": drive_path,
            "scan_path": scan_target,
            "status": "UNSAFE",
            "threats": len(detected_files) or 1,
            "detected_files": detected_files,
            "sha256": sha256,
            "threat_ids": threat_ids,
            "remediation_status": remediation_status,
            "detection_engine": detection_engine,
            "yara_rules": yara_matches,
            "files_discovered": yara_discovered_files,
            "files_scanned": yara_scanned_files,
            "scan_errors": yara_error_count,
            "duration": scan_duration
        }

    
    # -----------------------------------------
    # ERROR
    # -----------------------------------------

    message = result.get(
        "message",
        "Unknown error"
    )

    return {
        "device": drive["DiskName"],
        "drive": drive_path,
        "scan_path": scan_target,
        "status": "ERROR",
        "message": message,
        "duration": scan_duration
    }
