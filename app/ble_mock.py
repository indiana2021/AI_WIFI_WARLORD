# ble_mock.py
# This file provides a mock implementation of a Bluetooth Low Energy (BLE)
# interface for the AI Network Guardian. It simulates the behavior of a real
# BLE library for development and testing purposes when no actual
# Bluetooth hardware is present.

import time
import threading

class MockBLE:
    """
    A mock class that simulates a BLE interface, including advertising,
    a GATT server, and characteristic notifications.
    """
    def __init__(self, device_name="NetworkGuardian_BLE"):
        self.device_name = device_name
        self.is_advertising = False
        self.is_listening = False
        self.status_subscribers = []

    def start_advertising(self):
        """Simulates the start of BLE advertising."""
        if not self.is_advertising:
            print(f"[BLE Mock] Starting advertising as '{self.device_name}'...")
            self.is_advertising = True
        else:
            print("[BLE Mock] Already advertising.")

    def stop_advertising(self):
        """Simulates stopping BLE advertising."""
        if self.is_advertising:
            print("[BLE Mock] Stopping advertising.")
            self.is_advertising = False
        else:
            print("[BLE Mock] Not currently advertising.")

    def start_gatt_server(self):
        """Simulates starting a GATT server to listen for connections."""
        if not self.is_listening:
            print("[BLE Mock] GATT server started. Listening for connections and commands...")
            self.is_listening = True
            threading.Timer(30, self._simulate_command_reception).start()
        else:
            print("[BLE Mock] GATT server is already running.")

    def stop_gatt_server(self):
        """Simulates stopping the GATT server."""
        if self.is_listening:
            print("[BLE Mock] GATT server stopped.")
            self.is_listening = False
        else:
            print("[BLE Mock] GATT server is not running.")

    def notify_status(self, status_data):
        """
        Simulates sending a notification with status data to subscribed clients.
        """
        if self.is_listening and self.status_subscribers:
            print(f"[BLE Mock] Notifying {len(self.status_subscribers)} subscribers with status: {status_data}")
        else:
            pass

    def _simulate_command_reception(self):
        """A private method to simulate a command being received via BLE."""
        if self.is_listening:
            print("[BLE Mock] Simulated command received: 'toggle_guardian_state'")
            self.status_subscribers.append("mock_client_1")
            print("[BLE Mock] A mock client has subscribed to status updates.")

# A global instance of the mock BLE interface to be used by the main application.
mock_ble_interface = MockBLE()
