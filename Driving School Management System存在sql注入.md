
### 基本信息
在admin/sortData/fetch.php中将start_date end_date search参数直接拼接入sql语句造成的sql注入

```php
$query = "SELECT * FROM `cust_details`  WHERE ";

if ($_POST["is_date_search"] == "yes") {
    $query .= 'date BETWEEN "' . $_POST["start_date"] . '" AND "' . $_POST["end_date"] . '" AND ';
}

if (isset($_POST["search"]["value"])) {
    $query .= '
  (id LIKE "%' . $_POST["search"]["value"] . '%" 
  OR name LIKE "%' . $_POST["search"]["value"] . '%" 
  OR vehicle LIKE "%' . $_POST["search"]["value"] . '%" 
  OR totalamount LIKE "%' . $_POST["search"]["value"] . '%")
 ';
}

if (isset($_POST["order"])) {
    $query .= 'ORDER BY ' . $columns[$_POST['order']['0']['column']] . ' ' . $_POST['order']['0']['dir'] . ' 
 ';
} else {
    $query .= 'ORDER BY id DESC ';
}

$query1 = '';

if ($_POST["length"] != -1) {
    $query1 = 'LIMIT ' . $_POST['start'] . ', ' . $_POST['length'];
}

$number_filter_row = mysqli_num_rows(mysqli_query($connect, $query));
```


### 攻击场景

1. 攻击者在搜索值、日期或排序参数中注入 SQL 片段，读取、筛选或破坏 `cust_details` 数据。

### 防御建议

1. 使用 PDO 预编译语句
2. 使用 MySQLi 预编译语句
3. 不要拼接字符串

### 修复代码

使用参数化查询；排序列必须从固定白名单取值，分页参数强制转整数。

```php
<?php
require_once __DIR__ . '/../../includes/authentication.php';
require_admin();

$columns = ['id', 'name', 'phone', 'totalamount', 'paidamount', 'dueamount', 'vehicle', 'trainername', 'date', 'days', 'endedAT'];
$orderColumnIndex = filter_input(INPUT_POST, 'order.0.column', FILTER_VALIDATE_INT);
$orderColumn = $columns[$orderColumnIndex] ?? 'id';
$orderDir = strtolower($_POST['order'][0]['dir'] ?? 'desc') === 'asc' ? 'ASC' : 'DESC';
$start = max(0, (int)($_POST['start'] ?? 0));
$length = min(100, max(1, (int)($_POST['length'] ?? 25)));
$search = '%' . ($_POST['search']['value'] ?? '') . '%';

$sql = "SELECT id, name, phone, totalamount, paidamount, dueamount, vehicle, trainername, date, days, endedAT
        FROM cust_details
        WHERE name LIKE ? OR phone LIKE ? OR vehicle LIKE ?
        ORDER BY $orderColumn $orderDir
        LIMIT ?, ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param('sssii', $search, $search, $search, $start, $length);
$stmt->execute();
$result = $stmt->get_result();
```

