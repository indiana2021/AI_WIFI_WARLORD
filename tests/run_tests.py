#!/usr/bin/env python3
"""
Comprehensive test runner for AI Network Guardian
Runs all tests systematically and provides detailed reporting
"""

import subprocess
import sys
import os
import time
import json
from pathlib import Path

def run_command(cmd, description):
    """Run a command and return success status and output"""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")
    print('='*60)
    
    start_time = time.time()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        duration = time.time() - start_time
        
        if result.returncode == 0:
            print(f"✅ SUCCESS ({duration:.2f}s)")
            return True, result.stdout, result.stderr, duration
        else:
            print(f"❌ FAILED ({duration:.2f}s)")
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
            return False, result.stdout, result.stderr, duration
            
    except subprocess.TimeoutExpired:
        print(f"⏰ TIMEOUT (>300s)")
        return False, "", "Test timed out", 300
    except Exception as e:
        print(f"💥 ERROR: {e}")
        return False, "", str(e), 0

def run_basic_tests():
    """Run basic functionality tests"""
    print("\n🔍 RUNNING BASIC FUNCTIONALITY TESTS")
    
    tests = [
        (["python", "-c", "import guardian_main; print('Import successful')"], 
         "Module Import Test"),
        (["python", "-c", "from guardian_main import guardian_state; print('State initialized')"], 
         "Global State Test"),
        (["python", "-c", "from guardian_main import update_status; update_status('test'); print('Status update works')"], 
         "Status Update Test"),
    ]
    
    results = []
    for cmd, desc in tests:
        success, stdout, stderr, duration = run_command(cmd, desc)
        results.append({
            "test": desc,
            "success": success,
            "duration": duration,
            "stdout": stdout,
            "stderr": stderr
        })
    
    return results

def run_pytest_tests():
    """Run pytest test suite"""
    print("\n🧪 RUNNING PYTEST TEST SUITE")
    
    # Run with verbose output and coverage
    cmd = [
        "python", "-m", "pytest", 
        "tests/test_guardian_main.py", 
        "-v", 
        "--tb=short",
        "--durations=10"
    ]
    
    success, stdout, stderr, duration = run_command(cmd, "Pytest Test Suite")
    
    return [{
        "test": "Pytest Test Suite",
        "success": success,
        "duration": duration,
        "stdout": stdout,
        "stderr": stderr
    }]

def run_flask_tests():
    """Run Flask web dashboard tests"""
    print("\n🌐 RUNNING FLASK WEB DASHBOARD TESTS")
    
    # Test Flask app can be imported
    cmd = ["python", "-c", """
import sys
sys.path.append('app')
from guardian_main import web_app
print('Flask app imported successfully')
print(f'App name: {web_app.name}')
print(f'App routes: {len(web_app.url_map._rules)}')
"""]
    
    success, stdout, stderr, duration = run_command(cmd, "Flask App Import Test")
    
    return [{
        "test": "Flask App Import Test",
        "success": success,
        "duration": duration,
        "stdout": stdout,
        "stderr": stderr
    }]

def run_dependency_tests():
    """Test that all required dependencies are available"""
    print("\n📦 RUNNING DEPENDENCY TESTS")
    
    dependencies = [
        "flask", "pyzmq", "paramiko", "nmap", "asyncssh", 
        "pytest", "requests", "serial", "json", "threading"
    ]
    
    results = []
    for dep in dependencies:
        cmd = ["python", "-c", f"import {dep}; print('{dep} imported successfully')"]
        success, stdout, stderr, duration = run_command(cmd, f"Import {dep}")
        results.append({
            "test": f"Import {dep}",
            "success": success,
            "duration": duration,
            "stdout": stdout,
            "stderr": stderr
        })
    
    return results

def run_system_tool_tests():
    """Test that system tools are available (mocked)"""
    print("\n🔧 RUNNING SYSTEM TOOL TESTS")
    
    # Test that the code can handle missing tools gracefully
    cmd = ["python", "-c", """
import sys
sys.path.append('app')
from guardian_main import WiFiSecurityModule
wifi = WiFiSecurityModule('wlan0')
print('WiFiSecurityModule initialized')
"""]
    
    success, stdout, stderr, duration = run_command(cmd, "System Tool Handling Test")
    
    return [{
        "test": "System Tool Handling Test",
        "success": success,
        "duration": duration,
        "stdout": stdout,
        "stderr": stderr
    }]

def run_performance_tests():
    """Run basic performance tests"""
    print("\n⚡ RUNNING PERFORMANCE TESTS")
    
    # Test state update performance
    cmd = ["python", "-c", """
import time
import sys
sys.path.append('app')
from guardian_main import update_status, guardian_state

start_time = time.time()
for i in range(1000):
    update_status(f'Performance test message {i}')
end_time = time.time()

print(f'1000 status updates in {end_time - start_time:.3f}s')
print(f'Average: {(end_time - start_time) / 1000 * 1000:.2f}ms per update')
print(f'Log stream length: {len(guardian_state["log_stream"])}')
"""]
    
    success, stdout, stderr, duration = run_command(cmd, "State Update Performance Test")
    
    return [{
        "test": "State Update Performance Test",
        "success": success,
        "duration": duration,
        "stdout": stdout,
        "stderr": stderr
    }]

def generate_report(all_results):
    """Generate a comprehensive test report"""
    print("\n" + "="*80)
    print("📊 COMPREHENSIVE TEST REPORT")
    print("="*80)
    
    total_tests = len(all_results)
    passed_tests = sum(1 for r in all_results if r["success"])
    failed_tests = total_tests - passed_tests
    total_duration = sum(r["duration"] for r in all_results)
    
    print(f"\n📈 SUMMARY:")
    print(f"   Total Tests: {total_tests}")
    print(f"   Passed: {passed_tests} ✅")
    print(f"   Failed: {failed_tests} ❌")
    print(f"   Success Rate: {(passed_tests/total_tests)*100:.1f}%")
    print(f"   Total Duration: {total_duration:.2f}s")
    
    if failed_tests > 0:
        print(f"\n❌ FAILED TESTS:")
        for result in all_results:
            if not result["success"]:
                print(f"   - {result['test']}")
                if result["stderr"]:
                    print(f"     Error: {result['stderr'][:200]}...")
    
    print(f"\n✅ PASSED TESTS:")
    for result in all_results:
        if result["success"]:
            print(f"   - {result['test']} ({result['duration']:.2f}s)")
    
    # Save detailed report
    report_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "success_rate": (passed_tests/total_tests)*100,
            "total_duration": total_duration
        },
        "results": all_results
    }
    
    with open("test_report.json", "w") as f:
        json.dump(report_data, f, indent=2)
    
    print(f"\n📄 Detailed report saved to: test_report.json")
    
    return passed_tests == total_tests

def main():
    """Main test runner"""
    print("🚀 AI NETWORK GUARDIAN - COMPREHENSIVE TEST SUITE")
    print("="*80)
    
    # Change to project root
    os.chdir(Path(__file__).parent.parent)
    
    all_results = []
    
    # Run all test categories
    all_results.extend(run_basic_tests())
    all_results.extend(run_dependency_tests())
    all_results.extend(run_system_tool_tests())
    all_results.extend(run_flask_tests())
    all_results.extend(run_pytest_tests())
    all_results.extend(run_performance_tests())
    
    # Generate report
    all_passed = generate_report(all_results)
    
    print(f"\n{'='*80}")
    if all_passed:
        print("🎉 ALL TESTS PASSED! The AI Network Guardian is ready for deployment.")
    else:
        print("⚠️  SOME TESTS FAILED. Please review the report above and fix issues.")
    print("="*80)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main()) 