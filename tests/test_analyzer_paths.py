"""
Tests for analyzer path handling and exit code behavior
"""
import sys
import os
import tempfile
import pytest

from analyzer import SecurityAnalyzer


class TestRelativePaths:
    """Tests for relative path display in analyzer"""
    
    def test_analyzer_uses_relative_paths(self, tmp_path):
        """Test that analyzer returns relative paths in results"""
        # Create a test directory structure
        test_dir = tmp_path / "test_project"
        test_dir.mkdir()
        subdir = test_dir / "ethereum"
        subdir.mkdir()
        
        # Create a test file with a known vulnerability
        test_file = subdir / "vulnerable.sol"
        test_file.write_text("""
        contract Test {
            function transfer() public {
                require(tx.origin == msg.sender);
            }
        }
        """)
        
        # Initialize analyzer
        rules_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'vulnerability_rules.json')
        analyzer = SecurityAnalyzer(rules_path)
        
        # Analyze the directory
        results = analyzer.analyze_repository(str(test_dir))
        
        # Check that results contain relative paths
        assert results['total_files'] > 0
        
        # Check files_analyzed uses relative paths
        for file_info in results['files_analyzed']:
            filepath = file_info['filepath']
            # Should not be an absolute path
            assert not os.path.isabs(filepath), f"Path should be relative but got: {filepath}"
            # Should not contain the temp directory path
            assert str(tmp_path) not in filepath, f"Path should not contain temp dir: {filepath}"
    
    def test_analyzer_relative_path_in_vulnerabilities(self, tmp_path):
        """Test that vulnerabilities contain relative paths"""
        # Create a test directory structure
        test_dir = tmp_path / "test_project"
        test_dir.mkdir()
        
        # Create a test file with a known vulnerability
        test_file = test_dir / "vulnerable.sol"
        test_file.write_text("""
        contract Test {
            function transfer() public {
                require(tx.origin == msg.sender);
            }
        }
        """)
        
        # Initialize analyzer
        rules_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'vulnerability_rules.json')
        analyzer = SecurityAnalyzer(rules_path)
        
        # Analyze the directory
        results = analyzer.analyze_repository(str(test_dir))
        
        # Check that vulnerabilities contain relative paths
        if results['details']:
            for detail in results['details']:
                filepath = detail['filepath']
                # Should not be an absolute path
                assert not os.path.isabs(filepath), f"Vulnerability path should be relative but got: {filepath}"
                # Should be just the filename
                assert filepath == "vulnerable.sol", f"Expected 'vulnerable.sol' but got: {filepath}"
                
                # Check vulnerabilities in the detail
                for vuln in detail.get('vulnerabilities', []):
                    vuln_path = vuln.get('filepath', '')
                    assert not os.path.isabs(vuln_path), f"Vulnerability filepath should be relative: {vuln_path}"
    
    def test_analyzer_nested_directory_relative_paths(self, tmp_path):
        """Test relative paths work correctly with nested directories"""
        # Create nested directory structure
        test_dir = tmp_path / "project"
        test_dir.mkdir()
        nested_dir = test_dir / "contracts" / "ethereum"
        nested_dir.mkdir(parents=True)
        
        # Create a test file
        test_file = nested_dir / "token.sol"
        test_file.write_text("""
        contract Token {
            function auth() public {
                require(tx.origin == owner);
            }
        }
        """)
        
        # Initialize analyzer
        rules_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'vulnerability_rules.json')
        analyzer = SecurityAnalyzer(rules_path)
        
        # Analyze the directory
        results = analyzer.analyze_repository(str(test_dir))
        
        # Check that paths are relative from project root
        if results['files_analyzed']:
            for file_info in results['files_analyzed']:
                filepath = file_info['filepath']
                # Should be relative path with subdirectories
                assert 'contracts/ethereum/token.sol' in filepath or 'contracts\\ethereum\\token.sol' in filepath, \
                    f"Expected nested path but got: {filepath}"
                # Should not contain temp directory
                assert str(tmp_path) not in filepath


class TestExitCodeBehavior:
    """Tests for exit code behavior in main module"""
    
    def test_main_returns_zero_by_default_with_critical(self, tmp_path, capsys):
        """Test that main.py returns 0 even with CRITICAL issues by default"""
        # Import main module
        import main
        
        # Create a test file with critical vulnerability
        test_dir = tmp_path / "test_project"
        test_dir.mkdir()
        test_file = test_dir / "vulnerable.sol"
        test_file.write_text("""
        contract Test {
            function transfer() public {
                require(tx.origin == msg.sender);
            }
        }
        """)
        
        # Mock sys.argv to pass arguments
        old_argv = sys.argv
        try:
            sys.argv = ['main.py', '--target', str(test_dir)]
            exit_code = main.main()
            # Should return 0 (success) even with CRITICAL issues
            assert exit_code == 0, f"Expected exit code 0 but got {exit_code}"
        finally:
            sys.argv = old_argv
    
    def test_main_returns_one_in_strict_mode_with_critical(self, tmp_path, capsys):
        """Test that main.py returns 1 with --strict flag when CRITICAL issues found"""
        import main
        
        # Create a test file with critical vulnerability
        test_dir = tmp_path / "test_project"
        test_dir.mkdir()
        test_file = test_dir / "vulnerable.sol"
        test_file.write_text("""
        contract Test {
            function transfer() public {
                require(tx.origin == msg.sender);
            }
        }
        """)
        
        # Mock sys.argv with --strict flag
        old_argv = sys.argv
        try:
            sys.argv = ['main.py', '--target', str(test_dir), '--strict']
            exit_code = main.main()
            # Should return 1 (failure) with CRITICAL issues in strict mode
            assert exit_code == 1, f"Expected exit code 1 in strict mode but got {exit_code}"
        finally:
            sys.argv = old_argv
    
    def test_main_returns_zero_in_strict_mode_without_critical(self, tmp_path, capsys):
        """Test that main.py returns 0 with --strict flag when no CRITICAL issues"""
        import main
        
        # Create a test file without vulnerabilities
        test_dir = tmp_path / "test_project"
        test_dir.mkdir()
        test_file = test_dir / "safe.py"
        test_file.write_text("""
        def safe_function():
            return "Hello World"
        """)
        
        # Mock sys.argv with --strict flag
        old_argv = sys.argv
        try:
            sys.argv = ['main.py', '--target', str(test_dir), '--strict']
            exit_code = main.main()
            # Should return 0 (success) without CRITICAL issues even in strict mode
            assert exit_code == 0, f"Expected exit code 0 but got {exit_code}"
        finally:
            sys.argv = old_argv
