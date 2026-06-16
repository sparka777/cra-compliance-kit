"""Quick launcher for SBOM generator - run this directly."""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from sbom.generator import generate, main
if __name__ == "__main__":
    main()
