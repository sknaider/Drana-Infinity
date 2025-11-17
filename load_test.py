#!/usr/bin/env python3
"""
Load Testing Script for Drana-Infinity
Tests scalability under concurrent load
"""

import requests
import threading
import time
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

class LoadTester:
    def __init__(self, base_url='http://127.0.0.1:80'):
        self.base_url = base_url
        self.results = {
            'success': [],
            'failures': [],
            'latencies': [],
            'errors': []
        }
        self.lock = threading.Lock()

    def test_endpoint(self, endpoint, method='GET', data=None, cookies=None):
        """Test a single endpoint"""
        start = time.time()
        try:
            if method == 'GET':
                response = requests.get(f"{self.base_url}{endpoint}", timeout=10, cookies=cookies)
            else:
                response = requests.post(f"{self.base_url}{endpoint}", json=data, timeout=10, cookies=cookies)

            latency = (time.time() - start) * 1000  # ms

            with self.lock:
                if response.status_code < 400:
                    self.results['success'].append(endpoint)
                    self.results['latencies'].append(latency)
                else:
                    self.results['failures'].append({
                        'endpoint': endpoint,
                        'status': response.status_code,
                        'latency': latency
                    })

            return True, latency, response.status_code

        except Exception as e:
            latency = (time.time() - start) * 1000
            with self.lock:
                self.results['errors'].append({
                    'endpoint': endpoint,
                    'error': str(e),
                    'latency': latency
                })
            return False, latency, str(e)

    def concurrent_test(self, endpoint, concurrent_users, requests_per_user=10):
        """Test with concurrent users"""
        print(f"\n{'='*70}")
        print(f"Testing: {endpoint}")
        print(f"Concurrent Users: {concurrent_users}")
        print(f"Requests per User: {requests_per_user}")
        print(f"Total Requests: {concurrent_users * requests_per_user}")
        print(f"{'='*70}\n")

        # Reset results
        self.results = {
            'success': [],
            'failures': [],
            'latencies': [],
            'errors': []
        }

        start_time = time.time()

        def user_session():
            for _ in range(requests_per_user):
                self.test_endpoint(endpoint)

        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            futures = [executor.submit(user_session) for _ in range(concurrent_users)]
            for future in as_completed(futures):
                future.result()

        total_time = time.time() - start_time

        # Calculate metrics
        total_requests = len(self.results['success']) + len(self.results['failures']) + len(self.results['errors'])
        success_rate = (len(self.results['success']) / total_requests * 100) if total_requests > 0 else 0
        avg_latency = statistics.mean(self.results['latencies']) if self.results['latencies'] else 0
        min_latency = min(self.results['latencies']) if self.results['latencies'] else 0
        max_latency = max(self.results['latencies']) if self.results['latencies'] else 0
        requests_per_sec = total_requests / total_time if total_time > 0 else 0

        # Print results
        print(f"Results:")
        print(f"  Total Requests: {total_requests}")
        print(f"  Successful: {len(self.results['success'])} ({success_rate:.1f}%)")
        print(f"  Failed: {len(self.results['failures'])}")
        print(f"  Errors: {len(self.results['errors'])}")
        print(f"\nPerformance:")
        print(f"  Total Time: {total_time:.2f}s")
        print(f"  Requests/sec: {requests_per_sec:.2f}")
        print(f"  Avg Latency: {avg_latency:.2f}ms")
        print(f"  Min Latency: {min_latency:.2f}ms")
        print(f"  Max Latency: {max_latency:.2f}ms")

        if self.results['errors']:
            print(f"\nErrors:")
            error_types = {}
            for error in self.results['errors']:
                error_msg = error['error']
                error_types[error_msg] = error_types.get(error_msg, 0) + 1

            for error_msg, count in error_types.items():
                print(f"  {error_msg}: {count}")

        # Determine grade
        if success_rate >= 99 and avg_latency < 100:
            grade = "A+ EXCELLENT"
        elif success_rate >= 95 and avg_latency < 200:
            grade = "A GOOD"
        elif success_rate >= 90 and avg_latency < 500:
            grade = "B ACCEPTABLE"
        elif success_rate >= 80:
            grade = "C POOR"
        else:
            grade = "F FAILING"

        print(f"\nGrade: {grade}")
        print(f"{'='*70}\n")

        return {
            'total_requests': total_requests,
            'success_rate': success_rate,
            'avg_latency': avg_latency,
            'requests_per_sec': requests_per_sec,
            'grade': grade
        }


def main():
    print("""
    ╔════════════════════════════════════════════════════════════════╗
    ║            DRANA-INFINITY LOAD TESTING SUITE                  ║
    ╚════════════════════════════════════════════════════════════════╝
    """)

    tester = LoadTester()

    # Check if server is running
    try:
        response = requests.get('http://127.0.0.1:80', timeout=5)
        print("✓ Server is running\n")
    except:
        print("✗ Server is NOT running!")
        print("\nPlease start the server first:")
        print("  sudo python3 drana_infinity.py\n")
        return

    # Test scenarios
    scenarios = [
        {'name': 'Light Load', 'users': 10, 'requests': 5},
        {'name': 'Medium Load', 'users': 50, 'requests': 10},
        {'name': 'Heavy Load', 'users': 100, 'requests': 10},
    ]

    results = []

    for scenario in scenarios:
        print(f"\n{'#'*70}")
        print(f"SCENARIO: {scenario['name']}")
        print(f"{'#'*70}")

        result = tester.concurrent_test(
            '/',
            concurrent_users=scenario['users'],
            requests_per_user=scenario['requests']
        )
        results.append({
            'scenario': scenario['name'],
            **result
        })

        # Wait between tests
        time.sleep(2)

    # Summary
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}\n")

    print(f"{'Scenario':<20} {'Req/s':<10} {'Latency':<12} {'Success':<10} {'Grade':<15}")
    print(f"{'-'*70}")

    for result in results:
        print(f"{result['scenario']:<20} "
              f"{result['requests_per_sec']:<10.1f} "
              f"{result['avg_latency']:<12.1f} "
              f"{result['success_rate']:<10.1f}% "
              f"{result['grade']:<15}")

    print(f"\n{'='*70}")
    print("RECOMMENDATIONS")
    print(f"{'='*70}\n")

    last_result = results[-1]

    if last_result['success_rate'] >= 95:
        print("✓ System handles heavy load well")
        print("  → Can support 100+ concurrent users")
    elif last_result['success_rate'] >= 80:
        print("⚠ System struggles under heavy load")
        print("  → Consider implementing fixes from SECURITY_AUDIT.md")
        print("  → Current limit: ~50 concurrent users")
    else:
        print("✗ System fails under load")
        print("  → CRITICAL: Fix race conditions immediately")
        print("  → Review connection pool implementation")

    if last_result['avg_latency'] > 500:
        print("\n⚠ High latency detected")
        print("  → Check database indexes")
        print("  → Review SQLite configuration")
        print("  → Consider PostgreSQL migration")

    print(f"\n{'='*70}\n")


if __name__ == '__main__':
    main()
