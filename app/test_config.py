"""
Test configuration for AI Network Guardian
Demonstrates how to use the centralized configuration system
"""

import os
import sys
sys.path.append(os.path.dirname(__file__))

from config import *

def test_configuration():
    """Test the configuration system"""
    print("=== AI Network Guardian Configuration Test ===")
    
    # Test basic configuration
    print(f"SD Card Log Path: {SD_CARD_LOG_PATH}")
    print(f"WiFi Interface: {WIFI_AUDIT_INTERFACE}")
    print(f"LAN Interface: {LAN_INTERFACE}")
    print(f"Web Host: {WEB_HOST}")
    print(f"Web Port: {WEB_PORT}")
    print(f"Debug Mode: {DEBUG_MODE}")
    
    # Test tool configurations
    print(f"\nTool Timeouts:")
    for tool, timeout in TOOL_TIMEOUTS.items():
        print(f"  {tool}: {timeout}s")
    
    # Test package mappings
    print(f"\nPackage Mappings:")
    for tool, package in PACKAGE_MAPPINGS.items():
        print(f"  {tool} -> {package}")
    
    # Test validation
    try:
        validate_config()
        print("\n✅ Configuration validation passed")
    except ValueError as e:
        print(f"\n❌ Configuration validation failed: {e}")
    
    # Test environment overrides
    print(f"\nEnvironment Overrides:")
    print(f"  GUARDIAN_ENV: {os.environ.get('GUARDIAN_ENV', 'production')}")
    print(f"  DEFAULT_INTERFACE: {os.environ.get('DEFAULT_INTERFACE', 'not set')}")
    print(f"  WEB_PORT: {os.environ.get('WEB_PORT', 'not set')}")

if __name__ == "__main__":
    test_configuration() 