#!/usr/bin/env python3
"""
Venn Set Math Utilities

Provides functions for calculating and validating Venn diagram regions for tool detection overlaps.
"""

from typing import Dict, Tuple


def calculate_venn_regions(metrics: Dict) -> Tuple[int, int, int, int, int, int, int]:
    """
    Calculate the seven mutually exclusive regions of a three-set Venn diagram.

    Args:
        metrics: A dictionary containing tool_counts with the following keys:
                 'codeql', 'gosec', 'gopher', 'codeql_gosec', 'codeql_gopher',
                 'gosec_gopher', 'codeql_gosec_gopher'

    Returns:
        A tuple containing the seven region values in the following order:
        (codeql_only, gosec_only, gopher_only, codeql_gosec_only,
         codeql_gopher_only, gosec_gopher_only, all_three)
    """
    # Extract the raw counts
    tool_counts = metrics["tool_counts"]

    # Calculate the seven mutually exclusive regions
    codeql_only = (
        tool_counts["codeql"]
        - tool_counts["codeql_gosec"]
        - tool_counts["codeql_gopher"]
        + tool_counts["codeql_gosec_gopher"]
    )

    gosec_only = (
        tool_counts["gosec"]
        - tool_counts["codeql_gosec"]
        - tool_counts["gosec_gopher"]
        + tool_counts["codeql_gosec_gopher"]
    )

    gopher_only = (
        tool_counts["gopher"]
        - tool_counts["codeql_gopher"]
        - tool_counts["gosec_gopher"]
        + tool_counts["codeql_gosec_gopher"]
    )

    codeql_gosec_only = tool_counts["codeql_gosec"] - tool_counts["codeql_gosec_gopher"]

    codeql_gopher_only = (
        tool_counts["codeql_gopher"] - tool_counts["codeql_gosec_gopher"]
    )

    gosec_gopher_only = tool_counts["gosec_gopher"] - tool_counts["codeql_gosec_gopher"]

    all_three = tool_counts["codeql_gosec_gopher"]

    return (
        codeql_only,
        gosec_only,
        gopher_only,
        codeql_gosec_only,
        codeql_gopher_only,
        gosec_gopher_only,
        all_three,
    )


def calculate_venn_regions_4set(
    metrics: Dict,
) -> Tuple[int, int, int, int, int, int, int, int, int, int, int, int, int, int, int]:
    """
    Calculate the fifteen mutually exclusive regions of a four-set Venn diagram.

    Uses inclusion-exclusion principle to calculate each region correctly.
    Tools: A=codeql, B=gosec, C=gopher, D=snyk

    Args:
        metrics: A dictionary containing tool_counts with all 15 combinations:
                 'codeql', 'gosec', 'gopher', 'snyk' (4 individual)
                 'codeql_gosec', 'codeql_gopher', 'codeql_snyk', 'gosec_gopher', 'gosec_snyk', 'gopher_snyk' (6 pairs)
                 'codeql_gosec_gopher', 'codeql_gosec_snyk', 'codeql_gopher_snyk', 'gosec_gopher_snyk' (4 triples)
                 'codeql_gosec_gopher_snyk' (1 quadruple)

    Returns:
        A tuple containing the fifteen region values in the following order:
        (codeql_only, gosec_only, gopher_only, snyk_only,
         codeql_gosec_only, codeql_gopher_only, codeql_snyk_only,
         gosec_gopher_only, gosec_snyk_only, gopher_snyk_only,
         codeql_gosec_gopher_only, codeql_gosec_snyk_only, codeql_gopher_snyk_only, gosec_gopher_snyk_only,
         all_four)
    """
    tool_counts = metrics["tool_counts"]

    # Extract counts, defaulting to 0 if not present
    A = tool_counts.get("codeql", 0)
    B = tool_counts.get("gosec", 0)
    C = tool_counts.get("gopher", 0)
    D = tool_counts.get("snyk", 0)

    AB = tool_counts.get("codeql_gosec", 0)
    AC = tool_counts.get("codeql_gopher", 0)
    AD = tool_counts.get("codeql_snyk", 0)
    BC = tool_counts.get("gosec_gopher", 0)
    BD = tool_counts.get("gosec_snyk", 0)
    CD = tool_counts.get("gopher_snyk", 0)

    ABC = tool_counts.get("codeql_gosec_gopher", 0)
    ABD = tool_counts.get("codeql_gosec_snyk", 0)
    ACD = tool_counts.get("codeql_gopher_snyk", 0)
    BCD = tool_counts.get("gosec_gopher_snyk", 0)

    ABCD = tool_counts.get("codeql_gosec_gopher_snyk", 0)

    # Calculate 15 mutually exclusive regions using inclusion-exclusion principle

    # 1. Individual only regions (4)
    A_only = A - AB - AC - AD + ABC + ABD + ACD - ABCD
    B_only = B - AB - BC - BD + ABC + ABD + BCD - ABCD
    C_only = C - AC - BC - CD + ABC + ACD + BCD - ABCD
    D_only = D - AD - BD - CD + ABD + ACD + BCD - ABCD

    # 2. Pairwise only regions (6)
    AB_only = AB - ABC - ABD + ABCD
    AC_only = AC - ABC - ACD + ABCD
    AD_only = AD - ABD - ACD + ABCD
    BC_only = BC - ABC - BCD + ABCD
    BD_only = BD - ABD - BCD + ABCD
    CD_only = CD - ACD - BCD + ABCD

    # 3. Triple only regions (4)
    ABC_only = ABC - ABCD
    ABD_only = ABD - ABCD
    ACD_only = ACD - ABCD
    BCD_only = BCD - ABCD

    # 4. Quadruple region (1)
    all_four = ABCD

    return (
        A_only,
        B_only,
        C_only,
        D_only,
        AB_only,
        AC_only,
        AD_only,
        BC_only,
        BD_only,
        CD_only,
        ABC_only,
        ABD_only,
        ACD_only,
        BCD_only,
        all_four,
    )


def validate_venn_calculations(
    metrics: Dict,
    set_sizes: Tuple[int, int, int, int, int, int, int],
    title: str,
    verbose: bool = True,
) -> bool:
    """
    Validate the accuracy of Venn diagram calculations.

    Args:
        metrics: A dictionary containing tool_counts and total_locations
        set_sizes: A tuple containing the seven calculated Venn diagram regions
        title: A string describing the context of the validation (for logging)
        verbose: Whether to print detailed validation errors (default: True)

    Returns:
        True if all validations pass, False otherwise
    """
    is_valid = True
    tool_counts = metrics["tool_counts"]
    validation_errors = []

    # Unpack the set sizes
    (
        codeql_only,
        gosec_only,
        gopher_only,
        codeql_gosec_only,
        codeql_gopher_only,
        gosec_gopher_only,
        all_three,
    ) = set_sizes

    # 1. Sum Check: Sum of all regions should equal total_locations
    total_in_venn = sum(set_sizes)
    if total_in_venn != metrics["total_locations"]:
        error_msg = [
            f"\nValidation Error in {title}:",
            f"Sum of Venn regions ({total_in_venn}) != Total locations ({metrics['total_locations']})",
            f"Raw metrics: {metrics['tool_counts']}",
            "Calculated regions:",
            f"  CodeQL only: {set_sizes[0]}",
            f"  Gosec only: {set_sizes[1]}",
            f"  Gopher only: {set_sizes[2]}",
            f"  CodeQL+Gosec only: {set_sizes[3]}",
            f"  CodeQL+Gopher only: {set_sizes[4]}",
            f"  Gosec+Gopher only: {set_sizes[5]}",
            f"  All three: {set_sizes[6]}",
        ]
        validation_errors.extend(error_msg)
        is_valid = False

    # 2. Individual Tool Count Check
    codeql_total = codeql_only + codeql_gosec_only + codeql_gopher_only + all_three
    gosec_total = gosec_only + codeql_gosec_only + gosec_gopher_only + all_three
    gopher_total = gopher_only + codeql_gopher_only + gosec_gopher_only + all_three

    if codeql_total != tool_counts["codeql"]:
        error_msg = [
            f"\nValidation Error in {title}:",
            f"CodeQL total from Venn ({codeql_total}) != CodeQL count ({tool_counts['codeql']})",
        ]
        validation_errors.extend(error_msg)
        is_valid = False

    if gosec_total != tool_counts["gosec"]:
        error_msg = [
            f"\nValidation Error in {title}:",
            f"Gosec total from Venn ({gosec_total}) != Gosec count ({tool_counts['gosec']})",
        ]
        validation_errors.extend(error_msg)
        is_valid = False

    if gopher_total != tool_counts["gopher"]:
        error_msg = [
            f"\nValidation Error in {title}:",
            f"Gopher total from Venn ({gopher_total}) != Gopher count ({tool_counts['gopher']})",
        ]
        validation_errors.extend(error_msg)
        is_valid = False

    # 3. Pairwise Overlap Check
    codeql_gosec_total = codeql_gosec_only + all_three
    codeql_gopher_total = codeql_gopher_only + all_three
    gosec_gopher_total = gosec_gopher_only + all_three

    if codeql_gosec_total != tool_counts["codeql_gosec"]:
        error_msg = [
            f"\nValidation Error in {title}:",
            f"CodeQL+Gosec total from Venn ({codeql_gosec_total}) != CodeQL+Gosec count ({tool_counts['codeql_gosec']})",
        ]
        validation_errors.extend(error_msg)
        is_valid = False

    if codeql_gopher_total != tool_counts["codeql_gopher"]:
        error_msg = [
            f"\nValidation Error in {title}:",
            f"CodeQL+Gopher total from Venn ({codeql_gopher_total}) != CodeQL+Gopher count ({tool_counts['codeql_gopher']})",
        ]
        validation_errors.extend(error_msg)
        is_valid = False

    if gosec_gopher_total != tool_counts["gosec_gopher"]:
        error_msg = [
            f"\nValidation Error in {title}:",
            f"Gosec+Gopher total from Venn ({gosec_gopher_total}) != Gosec+Gopher count ({tool_counts['gosec_gopher']})",
        ]
        validation_errors.extend(error_msg)
        is_valid = False

    # Print validation errors if verbose mode is enabled
    if verbose and validation_errors:
        for line in validation_errors:
            print(line)

    return is_valid


def validate_venn_calculations_4set(
    metrics: Dict,
    set_sizes: Tuple[
        int, int, int, int, int, int, int, int, int, int, int, int, int, int, int
    ],
    title: str,
    verbose: bool = True,
) -> bool:
    """
    Validate the accuracy of 4-set Venn diagram calculations.

    Args:
        metrics: A dictionary containing tool_counts and total_locations
        set_sizes: A tuple containing the fifteen calculated Venn diagram regions
        title: A string describing the context of the validation (for logging)
        verbose: Whether to print detailed validation errors (default: True)

    Returns:
        True if all validations pass, False otherwise
    """
    is_valid = True
    tool_counts = metrics["tool_counts"]
    validation_errors = []

    # Unpack the set sizes (15 regions)
    (
        A_only,
        B_only,
        C_only,
        D_only,
        AB_only,
        AC_only,
        AD_only,
        BC_only,
        BD_only,
        CD_only,
        ABC_only,
        ABD_only,
        ACD_only,
        BCD_only,
        all_four,
    ) = set_sizes

    # 1. Sum Check: Sum of all regions should equal total_locations
    total_in_venn = sum(set_sizes)
    if total_in_venn != metrics["total_locations"]:
        error_msg = [
            f"\nValidation Error in {title}:",
            f"Sum of Venn regions ({total_in_venn}) != Total locations ({metrics['total_locations']})",
            f"Raw metrics: {tool_counts}",
            "Calculated regions:",
            f"  Individual: A={A_only}, B={B_only}, C={C_only}, D={D_only}",
            f"  Pairs: AB={AB_only}, AC={AC_only}, AD={AD_only}, BC={BC_only}, BD={BD_only}, CD={CD_only}",
            f"  Triples: ABC={ABC_only}, ABD={ABD_only}, ACD={ACD_only}, BCD={BCD_only}",
            f"  Quadruple: ABCD={all_four}",
        ]
        validation_errors.extend(error_msg)
        is_valid = False

    # 2. Individual Tool Count Check
    A_total = (
        A_only + AB_only + AC_only + AD_only + ABC_only + ABD_only + ACD_only + all_four
    )
    B_total = (
        B_only + AB_only + BC_only + BD_only + ABC_only + ABD_only + BCD_only + all_four
    )
    C_total = (
        C_only + AC_only + BC_only + CD_only + ABC_only + ACD_only + BCD_only + all_four
    )
    D_total = (
        D_only + AD_only + BD_only + CD_only + ABD_only + ACD_only + BCD_only + all_four
    )

    expected_A = tool_counts.get("codeql", 0)
    expected_B = tool_counts.get("gosec", 0)
    expected_C = tool_counts.get("gopher", 0)
    expected_D = tool_counts.get("snyk", 0)

    if A_total != expected_A:
        error_msg = [
            f"\nValidation Error in {title}:",
            f"CodeQL total from Venn ({A_total}) != CodeQL count ({expected_A})",
        ]
        validation_errors.extend(error_msg)
        is_valid = False

    if B_total != expected_B:
        error_msg = [
            f"\nValidation Error in {title}:",
            f"Gosec total from Venn ({B_total}) != Gosec count ({expected_B})",
        ]
        validation_errors.extend(error_msg)
        is_valid = False

    if C_total != expected_C:
        error_msg = [
            f"\nValidation Error in {title}:",
            f"Gopher total from Venn ({C_total}) != Gopher count ({expected_C})",
        ]
        validation_errors.extend(error_msg)
        is_valid = False

    if D_total != expected_D:
        error_msg = [
            f"\nValidation Error in {title}:",
            f"Snyk total from Venn ({D_total}) != Snyk count ({expected_D})",
        ]
        validation_errors.extend(error_msg)
        is_valid = False

    # 3. Pairwise Overlap Check
    pairwise_checks = [
        (
            "AB",
            AB_only + ABC_only + ABD_only + all_four,
            tool_counts.get("codeql_gosec", 0),
        ),
        (
            "AC",
            AC_only + ABC_only + ACD_only + all_four,
            tool_counts.get("codeql_gopher", 0),
        ),
        (
            "AD",
            AD_only + ABD_only + ACD_only + all_four,
            tool_counts.get("codeql_snyk", 0),
        ),
        (
            "BC",
            BC_only + ABC_only + BCD_only + all_four,
            tool_counts.get("gosec_gopher", 0),
        ),
        (
            "BD",
            BD_only + ABD_only + BCD_only + all_four,
            tool_counts.get("gosec_snyk", 0),
        ),
        (
            "CD",
            CD_only + ACD_only + BCD_only + all_four,
            tool_counts.get("gopher_snyk", 0),
        ),
    ]

    for pair_name, calculated_total, expected_total in pairwise_checks:
        if calculated_total != expected_total:
            error_msg = [
                f"\nValidation Error in {title}:",
                f"{pair_name} total from Venn ({calculated_total}) != {pair_name} count ({expected_total})",
            ]
            validation_errors.extend(error_msg)
            is_valid = False

    # 4. Triple Overlap Check
    triple_checks = [
        ("ABC", ABC_only + all_four, tool_counts.get("codeql_gosec_gopher", 0)),
        ("ABD", ABD_only + all_four, tool_counts.get("codeql_gosec_snyk", 0)),
        ("ACD", ACD_only + all_four, tool_counts.get("codeql_gopher_snyk", 0)),
        ("BCD", BCD_only + all_four, tool_counts.get("gosec_gopher_snyk", 0)),
    ]

    for triple_name, calculated_total, expected_total in triple_checks:
        if calculated_total != expected_total:
            error_msg = [
                f"\nValidation Error in {title}:",
                f"{triple_name} total from Venn ({calculated_total}) != {triple_name} count ({expected_total})",
            ]
            validation_errors.extend(error_msg)
            is_valid = False

    # 5. Quadruple Overlap Check
    if all_four != tool_counts.get("codeql_gosec_gopher_snyk", 0):
        error_msg = [
            f"\nValidation Error in {title}:",
            f"ABCD total from Venn ({all_four}) != ABCD count ({tool_counts.get('codeql_gosec_gopher_snyk', 0)})",
        ]
        validation_errors.extend(error_msg)
        is_valid = False

    # Print validation errors if verbose mode is enabled
    if verbose and validation_errors:
        for line in validation_errors:
            print(line)

    return is_valid


def test_venn_calculations():
    """
    Test the Venn diagram calculations with a known test case.

    Returns:
        True if tests pass, False otherwise
    """
    test_metrics = {
        "tool_counts": {
            "codeql": 10,  # |A|
            "gosec": 15,  # |B|
            "gopher": 8,  # |C|
            "codeql_gosec": 4,  # |A∩B|
            "codeql_gopher": 2,  # |A∩C|
            "gosec_gopher": 3,  # |B∩C|
            "codeql_gosec_gopher": 1,  # |A∩B∩C|
        },
        "total_locations": 25,
    }

    # Calculate the Venn regions
    set_sizes = calculate_venn_regions(test_metrics)

    # Expected results
    expected = (5, 9, 4, 3, 1, 2, 1)  # Order: A, B, C, AB, AC, BC, ABC

    # Unpack for easier comparison
    (
        codeql_only,
        gosec_only,
        gopher_only,
        codeql_gosec_only,
        codeql_gopher_only,
        gosec_gopher_only,
        all_three,
    ) = set_sizes

    # Print test results
    print("\nTesting Venn diagram calculations with known test case:")
    print("Raw metrics:", test_metrics["tool_counts"])
    print("\nCalculated regions:")

    region_names = [
        "CodeQL only",
        "Gosec only",
        "Gopher only",
        "CodeQL+Gosec only",
        "CodeQL+Gopher only",
        "Gosec+Gopher only",
        "All three",
    ]

    all_passed = True
    for i, (region, value, expected_value) in enumerate(
        zip(region_names, set_sizes, expected)
    ):
        print(f"  {region}: {value} (expected: {expected_value})")
        if value != expected_value:
            print(f"  Test failed for {region}: got {value}, expected {expected_value}")
            all_passed = False

    # Verify sum equals total locations
    total = sum(set_sizes)
    if total != test_metrics["total_locations"]:
        print(
            f"\nTest failed: Sum of regions ({total}) != Total locations ({test_metrics['total_locations']})"
        )
        all_passed = False
    else:
        print(
            f"\nSum check passed: Sum of regions ({total}) = Total locations ({test_metrics['total_locations']})"
        )

    # Validate with our validation function
    validation_result = validate_venn_calculations(test_metrics, set_sizes, "Test Case")
    if not validation_result:
        print("Validation function reported errors.")
        all_passed = False

    if all_passed:
        print("\nAll tests passed! Venn diagram calculations are correct.")
    else:
        print("\nSome tests failed. Please check the calculations.")

    return all_passed


def test_venn_calculations_4set():
    """
    Test the 4-set Venn diagram calculations with a known test case.

    Returns:
        True if tests pass, False otherwise
    """
    test_metrics = {
        "tool_counts": {
            # Individual tools
            "codeql": 15,  # |A|
            "gosec": 12,  # |B|
            "gopher": 10,  # |C|
            "snyk": 8,  # |D|
            # Pairwise overlaps
            "codeql_gosec": 5,  # |A∩B|
            "codeql_gopher": 4,  # |A∩C|
            "codeql_snyk": 3,  # |A∩D|
            "gosec_gopher": 4,  # |B∩C|
            "gosec_snyk": 3,  # |B∩D|
            "gopher_snyk": 2,  # |C∩D|
            # Triple overlaps
            "codeql_gosec_gopher": 2,  # |A∩B∩C|
            "codeql_gosec_snyk": 2,  # |A∩B∩D|
            "codeql_gopher_snyk": 1,  # |A∩C∩D|
            "gosec_gopher_snyk": 1,  # |B∩C∩D|
            # Quadruple overlap
            "codeql_gosec_gopher_snyk": 1,  # |A∩B∩C∩D|
        },
        "total_locations": 29,  # This will be the actual sum of the 15 regions
    }

    # Calculate the Venn regions
    set_sizes = calculate_venn_regions_4set(test_metrics)

    # Expected results - calculated manually using inclusion-exclusion principle
    # A_only = 15 - 5 - 4 - 3 + 2 + 2 + 1 - 1 = 7
    # B_only = 12 - 5 - 4 - 3 + 2 + 2 + 1 - 1 = 4
    # C_only = 10 - 4 - 4 - 2 + 2 + 1 + 1 - 1 = 3
    # D_only = 8 - 3 - 3 - 2 + 2 + 1 + 1 - 1 = 3
    # AB_only = 5 - 2 - 2 + 1 = 2
    # AC_only = 4 - 2 - 1 + 1 = 2
    # AD_only = 3 - 2 - 1 + 1 = 1
    # BC_only = 4 - 2 - 1 + 1 = 2
    # BD_only = 3 - 2 - 1 + 1 = 1
    # CD_only = 2 - 1 - 1 + 1 = 1
    # ABC_only = 2 - 1 = 1
    # ABD_only = 2 - 1 = 1
    # ACD_only = 1 - 1 = 0
    # BCD_only = 1 - 1 = 0
    # ABCD = 1
    # Total: 7+4+3+3+2+2+1+2+1+1+1+1+0+0+1 = 29 ✓

    expected = (7, 4, 3, 3, 2, 2, 1, 2, 1, 1, 1, 1, 0, 0, 1)

    # Print test results
    print("\nTesting 4-set Venn diagram calculations with known test case:")
    print("Raw metrics:", test_metrics["tool_counts"])
    print("\nCalculated regions:")

    region_names = [
        "CodeQL only",
        "Gosec only",
        "Gopher only",
        "Snyk only",
        "CodeQL+Gosec only",
        "CodeQL+Gopher only",
        "CodeQL+Snyk only",
        "Gosec+Gopher only",
        "Gosec+Snyk only",
        "Gopher+Snyk only",
        "CodeQL+Gosec+Gopher only",
        "CodeQL+Gosec+Snyk only",
        "CodeQL+Gopher+Snyk only",
        "Gosec+Gopher+Snyk only",
        "All four tools",
    ]

    all_passed = True
    for i, (region, value, expected_value) in enumerate(
        zip(region_names, set_sizes, expected)
    ):
        print(f"  {region}: {value} (expected: {expected_value})")
        if value != expected_value:
            print(f"  Test failed for {region}: got {value}, expected {expected_value}")
            all_passed = False

    # Verify sum equals total locations
    total = sum(set_sizes)
    if total != test_metrics["total_locations"]:
        print(
            f"\nTest failed: Sum of regions ({total}) != Total locations ({test_metrics['total_locations']})"
        )
        all_passed = False
    else:
        print(
            f"\nSum check passed: Sum of regions ({total}) = Total locations ({test_metrics['total_locations']})"
        )

    # Validate with our validation function
    validation_result = validate_venn_calculations_4set(
        test_metrics, set_sizes, "4-Set Test Case"
    )
    if not validation_result:
        print("Validation function reported errors.")
        all_passed = False

    if all_passed:
        print("\nAll 4-set tests passed! Venn diagram calculations are correct.")
    else:
        print("\nSome 4-set tests failed. Please check the calculations.")

    return all_passed

