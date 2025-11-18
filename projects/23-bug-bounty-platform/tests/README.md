# Bug Bounty Platform - Test Suite

This directory contains comprehensive unit tests for the Bug Bounty Platform.

## Test Coverage

### Modules Tested

- **test_report_generator.py**: Tests for vulnerability and program report generation
  - VulnerabilityReport class (Markdown, JSON, HTML generation)
  - ProgramReport class (program summary generation)
  - File saving functionality
  - Report format validation

- **test_bounty_program.py**: Tests for bug bounty program management
  - Program creation and lifecycle
  - Scope management
  - Reward tier configuration
  - Researcher access control
  - Program statistics and metrics
  - Search and export functionality

## Running Tests

### Run All Tests

```bash
# From the tests directory
python run_tests.py

# Or using unittest directly
python -m unittest discover -v
```

### Run Specific Test File

```bash
python -m unittest test_report_generator
python -m unittest test_bounty_program
```

### Run Specific Test Class

```bash
python -m unittest test_report_generator.TestVulnerabilityReport
python -m unittest test_bounty_program.TestProgramManager
```

### Run Specific Test Method

```bash
python -m unittest test_report_generator.TestVulnerabilityReport.test_generate_markdown
```

## Test Structure

Each test file follows this structure:

1. **Setup**: Initialize test data and objects
2. **Test Methods**: Individual test cases for each functionality
3. **Assertions**: Verify expected behavior
4. **Cleanup**: Remove temporary files if created

## Writing New Tests

When adding new tests, follow these guidelines:

1. Name test files as `test_<module_name>.py`
2. Use descriptive test method names: `test_<functionality>`
3. Include docstrings explaining what each test validates
4. Use setUp() for common test data
5. Clean up any created files in tearDown() or at test end
6. Aim for high code coverage

## Example Test

```python
def test_create_program(self):
    """Test program creation"""
    program = self.manager.create_program(
        name="Test Program",
        organization_id="org_123",
        description="Test bug bounty program"
    )

    self.assertIsInstance(program, BugBountyProgram)
    self.assertEqual(program.name, "Test Program")
    self.assertEqual(program.status, ProgramStatus.DRAFT)
```

## Test Data

Tests use realistic but fake data including:

- Vulnerability reports with CVSS scores
- Bug bounty programs with scope and rewards
- Researcher submissions and metrics
- Program statistics and performance data

## Coverage Goals

- **Unit Tests**: Test individual functions and methods
- **Integration Tests**: Test interaction between components
- **Edge Cases**: Test boundary conditions and error handling
- **Validation**: Test input validation and error messages

## Dependencies

Tests use Python's built-in `unittest` framework. No additional testing dependencies required.
