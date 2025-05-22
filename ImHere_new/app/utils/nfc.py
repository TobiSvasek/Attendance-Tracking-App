import threading
from smartcard.System import readers
from smartcard.Exceptions import NoCardException
from smartcard.util import toHexString
import hashlib
import time
from app import socketio
from app.models.employee import Employee
from flask import current_app

# Global variable to store the scanned card UID
scanned_card_uid = None

def nfc_card_scanner(app):
    """Continuously scans for NFC cards and emits event via WebSocket"""
    global scanned_card_uid
    try:
        r = readers()
        if not r:
            print("No NFC reader detected.")
            return

        reader = r[0]
        connection = reader.createConnection()
        last_uid = None

        while True:
            try:
                connection.connect()
                GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]
                response, sw1, sw2 = connection.transmit(GET_UID)

                if sw1 == 0x90 and sw2 == 0x00:
                    uid = toHexString(response)

                    if uid != last_uid:
                        last_uid = uid
                        print(f"Card detected: {uid}")
                        scanned_card_uid = uid  # Set the global variable

                        hashed_uid = hashlib.sha256(uid.encode()).hexdigest()

                        # Use the provided app context
                        with app.app_context():
                            employee = Employee.query.filter_by(uid=hashed_uid).first()

                            if employee:
                                print(f"Card belongs to employee_id={employee.id}")
                                socketio.emit('card_scanned', {'employee_id': employee.id})
                            else:
                                print("Card not assigned, emitting raw UID")
                                socketio.emit('card_scanned', {'uid': uid})

                else:
                    last_uid = None

            except NoCardException:
                last_uid = None
            except Exception as e:
                print(f"[NFC ERROR] {e}")
                time.sleep(1)

            time.sleep(0.1)  # Small delay to prevent high CPU usage

    except Exception as e:
        print(f"NFC scanner initialization error: {e}")

def start_nfc_scanner():
    """Start the NFC scanner in a background thread"""
    # Get the current app from the current_app proxy
    app = current_app._get_current_object()
    threading.Thread(target=nfc_card_scanner, args=(app,), daemon=True).start()
    print("NFC scanner thread started")
