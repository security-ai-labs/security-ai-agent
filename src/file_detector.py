import os
from typing import List, Tuple

class FileDetector:
    """Intelligently detects file types and blockchain chains"""
    
    # Files to ALWAYS skip - security agent files
    SKIP_FILES = {
        'main.py',
        'analyzer.py',
        'file_detector.py',
        'pattern_matcher.py',
        'report_generator.py',
        'github_pr_commenter.py',
        'requirements.txt',
        'README.md',
        '.gitignore',
        'setup.py',
    }
    
    # Directories to skip
    SKIP_DIRS = {
        '.git', '__pycache__', 'node_modules', '.venv', 'venv',
        'env', 'temp-agent', 'artifacts', 'dist', 'build',
        '.idea', '.vscode', '.github', '.pytest_cache', 'htmlcov',
        '.next', '.nuxt', 'coverage', '.yarn'
    }
    
    # Map file extensions to (chain, language)
    FILE_TYPES = {
        '.sol': ('ethereum', 'solidity'),
        '.rs': ('solana', 'rust'),
        '.js': ('web2', 'javascript'),
        '.ts': ('web2', 'typescript'),
        '.py': ('web2', 'python'),
        '.go': ('web2', 'go'),
        '.java': ('web2', 'java'),
        '.cs': ('web2', 'csharp'),
        '.rb': ('web2', 'ruby'),
        '.php': ('web2', 'php'),
    }
    
    @staticmethod
    def should_skip(filepath: str) -> bool:
        """Check if file should be skipped from analysis"""
        filename = os.path.basename(filepath)
        
        # Skip security agent files
        if filename in FileDetector.SKIP_FILES:
            return True
        
        # Skip hidden files
        if filename.startswith('.'):
            return True
        
        # Skip temp files
        if filename.startswith('temp-'):
            return True
        
        # Skip test files (optional - comment out if you want to test them)
        # if 'test' in filename.lower():
        #     return True
        
        return False
    
    @staticmethod
    def get_file_type(filepath: str) -> Tuple[str, str]:
        """Get chain and language for file
        
        Returns: (chain, language) tuple
        Examples:
            'contract.sol' -> ('ethereum', 'solidity')
            'program.rs' -> ('solana', 'rust')
            'script.js' -> ('web2', 'javascript')
        """
        ext = os.path.splitext(filepath)[1].lower()
        return FileDetector.FILE_TYPES.get(ext, ('unknown', 'unknown'))
    
    @staticmethod
    def find_files(directory: str = '.') -> List[Tuple[str, str, str]]:
        """Find all security-relevant files in directory
        
        Returns: List of (filepath, chain, language) tuples
        Example:
            [
                ('ethereum/token.sol', 'ethereum', 'solidity'),
                ('src/wallet.js', 'web2', 'javascript'),
            ]
        """
        files = []
        
        for root, dirs, filenames in os.walk(directory):
            # Remove skipped directories from traversal
            dirs[:] = [d for d in dirs if d not in FileDetector.SKIP_DIRS]
            
            for filename in filenames:
                filepath = os.path.join(root, filename)
                
                # Skip unwanted files
                if FileDetector.should_skip(filepath):
                    continue
                
                # Check if it's a security-relevant file
                chain, language = FileDetector.get_file_type(filepath)
                if chain != 'unknown':
                    files.append((filepath, chain, language))
        
        return sorted(files)