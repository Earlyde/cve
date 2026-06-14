# DrivePulse SQL Injection Vulnerability Research

## Overview

| Item | Value |
|--------|--------|
| Project | DrivePulse |
| Vulnerability Type | SQL Injection |
| CWE | CWE-89 |
| Severity | High |
| Discovery Method | Source Code Review |
| Research Type | Defensive Security Research |

---

## Summary

During a source-code review of the DrivePulse Driving School Management System, I identified multiple SQL injection vulnerabilities within the data retrieval functionality.

The vulnerable component directly concatenates user-controlled input into SQL statements without using parameterized queries.

Affected parameters include:

- start_date
- end_date
- search[value]
- order[0][column]
- order[0][dir]
- start
- length

Successful exploitation may allow an authenticated attacker to manipulate query logic and potentially access, modify, or destroy database records.

---

## Vulnerable Component

```text
admin/sortData/fetch.php
```

---

## Discovery Process

The issue was discovered through manual code review while analyzing database query construction.

The application dynamically builds SQL statements using string concatenation.

Example:

```php
if (isset($_POST["search"]["value"])) {
    $query .= '
    (
        id LIKE "%' . $_POST["search"]["value"] . '%"
        OR name LIKE "%' . $_POST["search"]["value"] . '%"
        OR vehicle LIKE "%' . $_POST["search"]["value"] . '%"
        OR totalamount LIKE "%' . $_POST["search"]["value"] . '%"
    )
    ';
}
```

User input is inserted directly into the query without validation or parameterization.

---

## Root Cause Analysis

### Root Cause #1

Dynamic SQL Construction

The application relies on:

```php
$query .= ...
```

instead of parameterized statements.

---

### Root Cause #2

Missing Input Validation

No validation is applied to:

```text
search[value]
start_date
end_date
order[0][dir]
start
length
```

before processing.

---

### Root Cause #3

Absence of Prepared Statements

The application primarily uses:

```php
mysqli_query()
```

instead of:

```php
prepare()
bind_param()
```

which separate data from executable SQL syntax.

---

### Root Cause #4

Incomplete Whitelisting

Although sortable columns are mapped internally, sort direction remains user-controlled.

---

## Security Impact

### Data Disclosure

Potential access to:

- Student Records
- Payment Information
- Instructor Data
- Administrative Accounts

---

### Business Data Manipulation

Attackers may alter stored records if database permissions allow write operations.

---

### Data Destruction

Malicious queries may remove business-critical information.

---

### Database Compromise

Over-privileged database accounts may increase impact.

Potentially dangerous functions include:

```sql
LOAD_FILE()
INTO OUTFILE()
```

---

## Remediation

### Use Prepared Statements

Example:

```php
$stmt = $conn->prepare("
SELECT *
FROM cust_details
WHERE
name LIKE ?
OR phone LIKE ?
OR vehicle LIKE ?
");
```

---

### Validate User Input

Apply strict validation to:

- Dates
- Pagination
- Sorting
- Search Parameters

---

### Implement Whitelist Controls

Example:

```php
$allowedColumns = [
'id',
'name',
'phone',
'totalamount',
'paidamount',
'dueamount',
'vehicle',
'trainername',
'date'
];
```

---

### Apply Least-Privilege Database Permissions

Restrict application accounts to only necessary privileges.

---

## Defensive Recommendations

1. Adopt prepared statements across the project.
2. Introduce a centralized database abstraction layer.
3. Implement SQL auditing.
4. Disable verbose production error messages.
5. Conduct periodic secure code reviews.

---

## Research Notes

This research was conducted through source-code review and defensive security analysis.

The purpose of this analysis is:

- Vulnerability identification
- Root cause analysis
- Secure coding improvement
- Data breach prevention

No offensive exploitation of live systems was performed.

---

## References

- CWE-89: SQL Injection
- OWASP Top 10 – Injection
- DrivePulse Project
- Public Disclosure: Issue #1

---

## Author

Researcher: Early

GitHub:

https://github.com/Earlyde

Repository:

https://github.com/Earlyde/cve

Contact:

Early@hnsldjy.icu

## References

### Original Disclosure

- Vulnerability Report:
  - https://github.com/Earlyde/cve/issues/1

### Security Standards

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ("SQL Injection")
  - https://cwe.mitre.org/data/definitions/89.html

- OWASP SQL Injection Prevention Cheat Sheet
  - https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Technical References

- MySQL Error-Based Injection Technique: FLOOR(RAND()) Collision
  - https://security.stackexchange.com/questions/89341/sql-injection-explain-this-query

### Risk Assessment

- CVSS v3.1 Calculator
  - https://www.first.org/cvss/calculator/3.1
