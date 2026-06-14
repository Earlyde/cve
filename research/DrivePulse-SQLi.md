# DrivePulse SQL Injection Vulnerability Analysis

## Vulnerability Information

| Item | Description |
|--------|--------|
| Product | DrivePulse |
| Vendor | https://github.com/Ayushx309/DrivePulse |
| Vulnerability Type | SQL Injection |
| CWE | CWE-89 |
| Severity | High |
| Affected Component | `admin/sortData/fetch.php` |
| Discovery Method | Source Code Review |
| Research Type | Defensive Security Research |
| Authentication Required | Administrative Access |
| User Interaction Required | No |

---

## Executive Summary

During a source-code review of the DrivePulse Driving School Management System, multiple SQL Injection vulnerabilities were identified within the data filtering and search functionality located in:

```text
admin/sortData/fetch.php
```

The application directly concatenates user-controlled input into SQL statements without proper validation or parameterization.

Affected parameters include:

- `start_date`
- `end_date`
- `search[value]`
- `order[0][dir]`
- `start`
- `length`

Successful exploitation may allow attackers to manipulate query logic, disclose sensitive information, tamper with business records, or compromise database integrity.

---

## Vulnerability Description

### Vulnerable Code

```php
$query = "SELECT * FROM `cust_details` WHERE ";

if ($_POST["is_date_search"] == "yes") {
    $query .= 'date BETWEEN "' .
        $_POST["start_date"] .
        '" AND "' .
        $_POST["end_date"] .
        '" AND ';
}

if (isset($_POST["search"]["value"])) {
    $query .= '
    (id LIKE "%' . $_POST["search"]["value"] . '%"
    OR name LIKE "%' . $_POST["search"]["value"] . '%"
    OR vehicle LIKE "%' . $_POST["search"]["value"] . '%"
    OR totalamount LIKE "%' . $_POST["search"]["value"] . '%")
    ';
}
```

The application dynamically constructs SQL statements using user-controlled input.

---

## Discovery Process

The issue was discovered during manual source-code review.

Analysis revealed that multiple user-controlled parameters are directly incorporated into SQL statements through string concatenation rather than parameterized queries.

Affected parameters include:

- `start_date`
- `end_date`
- `search[value]`
- `order[0][dir]`
- `start`
- `length`

---

## Root Cause Analysis

### Root Cause #1 – Dynamic SQL Construction

Application logic builds SQL queries through direct string concatenation:

```php
$query .= $_POST["search"]["value"];
```

instead of separating SQL syntax from user data.

### Root Cause #2 – Missing Input Validation

No validation is performed on:

```text
start_date
end_date
search[value]
order[0][dir]
start
length
```

before query construction.

### Root Cause #3 – Absence of Prepared Statements

The application relies on:

```php
mysqli_query()
```

instead of:

```php
prepare()
bind_param()
```

which prevents SQL Injection by separating data from executable SQL.

---

## Attack Scenario

An attacker may inject SQL fragments into:

- Search parameters
- Date filters
- Sorting controls
- Pagination parameters

Potential consequences include:

### Data Disclosure

Access to:

```text
cust_details
```

records containing:

- Student information
- Contact details
- Payment records
- Training schedules

### Business Data Manipulation

```sql
UPDATE cust_details
SET paidamount = 999999;
```

### Data Destruction

```sql
DELETE FROM cust_details;
```

---

## Security Impact

| Category | Impact |
|----------|----------|
| Confidentiality | High |
| Integrity | High |
| Availability | High |

---

## Remediation

### Recommended Controls

- Use PDO prepared statements
- Use MySQLi prepared statements
- Eliminate dynamic SQL concatenation
- Implement strict input validation
- Enforce allowlist-based sorting
- Restrict database privileges

### Secure Implementation Example

```php
$columns = [
    'id',
    'name',
    'phone',
    'totalamount',
    'paidamount',
    'dueamount',
    'vehicle',
    'trainername',
    'date',
    'days',
    'endedAT'
];

$orderColumn = $columns[$orderColumnIndex] ?? 'id';

$orderDir =
strtolower($_POST['order'][0]['dir'] ?? 'desc') === 'asc'
? 'ASC'
: 'DESC';

$start = max(0, (int)($_POST['start'] ?? 0));
$length = min(100, max(1, (int)($_POST['length'] ?? 25)));

$search = '%' . ($_POST['search']['value'] ?? '') . '%';

$stmt = $conn->prepare("
SELECT
id,
name,
phone,
totalamount,
paidamount,
dueamount,
vehicle,
trainername,
date,
days,
endedAT
FROM cust_details
WHERE
name LIKE ?
OR phone LIKE ?
OR vehicle LIKE ?
ORDER BY $orderColumn $orderDir
LIMIT ?, ?
");

$stmt->bind_param(
    'sssii',
    $search,
    $search,
    $search,
    $start,
    $length
);
```

---

## Defensive Value

This research demonstrates common SQL Injection anti-patterns frequently observed in PHP applications.

The findings help developers:

- Identify unsafe query construction
- Adopt parameterized queries
- Improve secure coding practices
- Reduce data breach risks
- Strengthen application security posture

---

## References

### Original Disclosure

- https://github.com/Earlyde/cve/issues/1

### Security Standards

- CWE-89  
  https://cwe.mitre.org/data/definitions/89.html

- OWASP SQL Injection Prevention Cheat Sheet  
  https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

- OWASP Top 10 A03:2021 Injection  
  https://owasp.org/Top10/A03_2021-Injection/

### Risk Assessment

- CVSS v3.1 Calculator  
  https://www.first.org/cvss/calculator/3.1

---

## Author

**Researcher:** Early

**GitHub:** https://github.com/Earlyde

**Research Repository:** https://github.com/Earlyde/cve

**Contact:** Early@hnsldjy.icu

---

## Disclaimer

This research was conducted through source-code review and defensive security analysis.

The objective of this disclosure is to support vulnerability remediation, secure software development, and data breach prevention.

No unauthorized testing was performed against production systems.
