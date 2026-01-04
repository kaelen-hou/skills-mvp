# Code Quality Review Checklist

## Naming Conventions

### Variables & Functions
- [ ] Names describe purpose, not type
- [ ] Boolean names are predicative (isActive, hasPermission)
- [ ] Functions named with verbs (getUserData, calculateTotal)
- [ ] Consistent naming style per language

```python
# BAD
x = get_data()
flag = True
def process(d):
    pass

# GOOD
user_profile = fetch_user_profile()
is_authenticated = True
def validate_payment(payment_details):
    pass
```

### Constants & Classes
- [ ] Constants in UPPER_CASE
- [ ] Classes in PascalCase
- [ ] Enums clearly named
- [ ] Private members prefixed appropriately

---

## Function Design

### Single Responsibility
- [ ] Functions do one thing well
- [ ] Function length reasonable (< 50 lines)
- [ ] Clear input/output contract
- [ ] Side effects documented or avoided

### Parameters
- [ ] Parameter count reasonable (< 5)
- [ ] Related parameters grouped into objects
- [ ] Default values sensible
- [ ] Parameter types clear

```python
# BAD: Too many parameters
def create_user(name, email, age, address, phone, company, role, is_active):
    pass

# GOOD: Grouped into object
def create_user(user_data: UserCreateRequest):
    pass
```

### Complexity
- [ ] Cyclomatic complexity acceptable (< 10)
- [ ] Nesting depth limited (< 4 levels)
- [ ] Guard clauses used for early returns
- [ ] Complex conditions extracted to named variables

---

## DRY Principle

### Code Duplication
- [ ] Similar code blocks extracted to functions
- [ ] Constants used instead of magic numbers
- [ ] Common patterns abstracted
- [ ] Configuration centralized

```python
# BAD: Magic numbers
if status == 200:
    process()

# GOOD: Constants
HTTP_OK = 200
if status == HTTP_OK:
    process()
```

### Abstraction Level
- [ ] Appropriate abstraction (not over-engineered)
- [ ] Common interfaces for similar operations
- [ ] Utility functions for repeated logic

---

## Error Handling

### Exception Handling
- [ ] Specific exceptions caught, not bare except
- [ ] Exceptions handled at appropriate level
- [ ] Error messages helpful and actionable
- [ ] Resources cleaned up (finally/context managers)

```python
# BAD
try:
    process()
except:
    pass

# GOOD
try:
    process()
except ValueError as e:
    logger.warning(f"Invalid value: {e}")
    raise ValidationError(f"Processing failed: {e}")
```

### Null/None Handling
- [ ] Null checks where needed
- [ ] Optional types used appropriately
- [ ] Default values provided sensibly
- [ ] Null object pattern considered

---

## Code Organization

### File Structure
- [ ] Related code grouped together
- [ ] Clear module boundaries
- [ ] Imports organized and minimal
- [ ] Circular dependencies avoided

### Separation of Concerns
- [ ] Business logic separate from I/O
- [ ] Presentation separate from data
- [ ] Configuration externalized
- [ ] Dependencies injected

---

## Documentation

### Comments
- [ ] Complex logic explained
- [ ] "Why" documented, not "what"
- [ ] No commented-out code
- [ ] TODO/FIXME addressed or tracked

### API Documentation
- [ ] Public functions documented
- [ ] Parameters and return values described
- [ ] Usage examples for complex APIs
- [ ] Edge cases noted

---

## Testing

### Test Coverage
- [ ] New code has tests
- [ ] Edge cases covered
- [ ] Error paths tested
- [ ] Integration points tested

### Test Quality
- [ ] Tests are readable and maintainable
- [ ] One assertion per test (guideline)
- [ ] Tests independent of each other
- [ ] Mocks/stubs used appropriately
