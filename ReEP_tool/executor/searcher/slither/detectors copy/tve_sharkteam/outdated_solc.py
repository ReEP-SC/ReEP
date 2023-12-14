"""
    Check if the latest version of solc is allowed to use
"""

import re
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.formatters.attributes.incorrect_solc import custom_format
from slither.core.compilation_unit import SlitherCompilationUnit

# group:
# 0: ^ > >= < <= (optional)
# 1: ' ' (optional)
# 2: version number
# 3: version number
# 4: version number

# pylint: disable=anomalous-backslash-in-string
PATTERN = re.compile("(\^|>|>=|<|<=)?([ ]+)?(\d+)\.(\d+)\.(\d+)")


class OutdatedSolc(AbstractDetector):
    """
    Check if an old version of solc is used
    """

    ARGUMENT = "outdated-solc"
    HELP = "Outdated Solidity version"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = (
        "https://github.com/crytic/slither/wiki/Detector-Documentation#outdated-version-of-solidity"
    )

    WIKI_TITLE = "Outdated version of Solidity"
    WIKI_DESCRIPTION = """
`solc` frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks.
We also recommend using the latest compiler version. """
    WIKI_RECOMMENDATION = """
Consider using the latest version of Solidity for testing."""

    NOT_LATEST_VERSION_TXT = (
        "is not in the latest compiler version. Consider deploying with the version "
    )
    LATEST_VERSION_TXT = "The latest version is "
    # Indicates the allowed versions. Must be formatted in increasing order.
    LATEST_VERSION = "0.8.3"

    # def __init__(self, logger):
    # # def __init__(self, compilation_unit: SlitherCompilationUnit, logger):
    #     # super().__init__(compilation_unit, logger)
    #     self.latest_solc = list(map(str, self.LATEST_VERSION.split(".")))
    #     self.OUTDATED_VERSION_TXT = (
    #         self.NOT_LATEST_VERSION_TXT
    #         + self.LATEST_VERSION[0 : self.LATEST_VERSION.rfind(".") + 1]
    #         + "*. "
    #         + self.LATEST_VERSION_TXT
    #         + self.LATEST_VERSION
    #     )

    def _check_version(self, version):
        if not version:
            return None
        op = version[0]
        if len(op) < 1 or op == "=":
            if version[2:] == self.latest_solc:
                pass
            else:
                return self.OUTDATED_VERSION_TXT
        elif op == "^":
            if version[3] != self.latest_solc[1]:
                return self.OUTDATED_VERSION_TXT
        elif op == "<":
            if int(version[3]) < int(self.latest_solc[1]):
                return self.OUTDATED_VERSION_TXT
            if int(version[3]) == int(self.latest_solc[1]) and int(version[4]) == 0:
                return self.OUTDATED_VERSION_TXT
        elif op == "<=":
            if int(version[3]) < int(self.latest_solc[1]):
                return self.OUTDATED_VERSION_TXT

        return None

    def _check_pragma(self, version):
        versions = PATTERN.findall(version)
        # versions = [('>=', '', '0', '4', '21'), ('<=', '', '0', '8', '0')]
        if len(versions) == 1:
            version = versions[0]
        elif len(versions) == 2:
            if versions[0][0] in ["<", "<="]:
                version = versions[0]
            else:
                version = versions[1]
        return self._check_version(version)

    def _detect(self):
        """
        Detects pragma statements that allow for outdated solc versions.
        :return: Returns the relevant JSON data for the findings.
        """
        # Detect all version related pragmas and check if they are disallowed.
        
        self.latest_solc = list(map(str, self.LATEST_VERSION.split(".")))
        self.OUTDATED_VERSION_TXT = (
            self.NOT_LATEST_VERSION_TXT
            + self.LATEST_VERSION[0 : self.LATEST_VERSION.rfind(".") + 1]
            + "*. "
            + self.LATEST_VERSION_TXT
            + self.LATEST_VERSION)
            
        results = []
        compilation_unit = self.compilation_unit
        pragma = compilation_unit.pragma_directives
        for p in pragma:
            # Skip any pragma directives which do not refer to version
            if len(p.directive) < 1 or p.directive[0] != "solidity":
                continue
            # This is version, so we test if it allowes to use the latest version.
            reason = self._check_pragma(p.version)
            if reason:
                info = ["Pragma version", p, f" {reason}\n"]
                results.append(self.generate_result(info))

        return results

    @staticmethod
    def _format(compilation_unit: SlitherCompilationUnit, result):
        custom_format(compilation_unit, result)
