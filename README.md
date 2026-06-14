DrivePulse SQL 注入漏洞安全研究报告

项目名称： DrivePulse
漏洞类型： SQL Injection（CWE-89）
风险等级： 高危（High）
影响范围： admin/sortData/fetch.php
发现来源： GitHub Issue #1《Driving School Management System存在sql注入》

一、漏洞概述

在 DrivePulse 后台数据查询模块 admin/sortData/fetch.php 中，用户可控参数：

start_date
end_date
search[value]
order[0][column]
order[0][dir]
start
length

被直接拼接进入 SQL 语句。

代码中未使用预编译语句（Prepared Statement），也未对排序字段进行白名单校验，导致攻击者能够构造恶意 SQL 片段影响数据库执行逻辑。

二、漏洞等级评估
项目	评级
攻击复杂度	低
权限要求	低（登录用户即可）
用户交互	无
数据泄露	高
数据篡改	高
数据删除	高
业务影响	高
综合评级	High

参考：

CWE-89 SQL Injection
OWASP Top10 A03:2021 Injection
三、漏洞成因分析
1. Search 参数直接拼接

原始代码：

if (isset($_POST["search"]["value"])) {
    $query .= '
    (id LIKE "%' . $_POST["search"]["value"] . '%"
    OR name LIKE "%' . $_POST["search"]["value"] . '%"
    OR vehicle LIKE "%' . $_POST["search"]["value"] . '%"
    OR totalamount LIKE "%' . $_POST["search"]["value"] . '%")
    ';
}

用户输入：

%" OR 1=1 --+

生成：

id LIKE "%%" OR 1=1 --+%"

结果：

WHERE TRUE

绕过查询条件。

2. 日期参数直接拼接

原始代码：

$query .= 'date BETWEEN "' .
$_POST["start_date"] .
'" AND "' .
$_POST["end_date"] .
'" AND ';

攻击输入：

2024-01-01" OR 1=1#

生成：

date BETWEEN "2024-01-01" OR 1=1#"
AND "2024-12-31"

导致 SQL 逻辑被污染。

3. ORDER BY 注入

原始代码：

$query .=
'ORDER BY ' .
$columns[$_POST['order']['0']['column']]
.' ' .
$_POST['order']['0']['dir'];

虽然列名来自数组：

$columns[]

但：

dir

来自用户输入。

攻击者可构造：

dir=desc,(SELECT SLEEP(5))

形成：

ORDER BY id desc,(SELECT SLEEP(5))

造成：

时间盲注
数据库资源消耗
DoS
4. LIMIT 注入

原始代码：

$query1 =
'LIMIT ' .
$_POST['start'] .
', ' .
$_POST['length'];

如果未强制整数：

length=10 UNION SELECT ...

可导致额外注入点。

四、实际风险分析

攻击者可实现：

数据泄露

读取：

users
staff
payments
trainers

等敏感表。

后台账号枚举

利用：

UNION SELECT

读取管理员账户。

敏感业务信息泄露

包括：

学员资料
联系方式
付款记录
驾驶培训记录
数据篡改

例如：

UPDATE cust_details
SET paidamount=999999
数据删除

例如：

DELETE FROM cust_details
数据库接管

在高权限数据库账户情况下可能进一步实现：

LOAD_FILE()
INTO OUTFILE()

最终导致：

WebShell写入
服务器接管
五、根本原因（Root Cause Analysis）

从防御角度看，本漏洞并非单一编码失误，而是多个安全控制缺失叠加造成：

原因1：动态SQL设计

系统采用：

$query .= ...

动态拼接查询。

这是 SQL 注入最常见根因。

原因2：缺少输入边界验证

未验证：

search
start_date
end_date
dir
start
length

合法性。

原因3：未采用参数化查询

项目整体使用：

mysqli_query()

字符串执行模式。

未采用：

prepare()
bind_param()

安全模式。

原因4：排序字段未完全白名单化

虽然列名经过数组映射：

$columns[]

但：

ASC
DESC

方向值仍然来自用户输入。

原因5：缺少统一数据库访问层

项目大量页面直接操作 SQL。

导致：

安全策略无法统一实施
漏洞容易重复出现
六、完整修复方案
第一阶段：紧急修复（立即执行）
修复搜索功能

改造：

$stmt = $conn->prepare("
SELECT *
FROM cust_details
WHERE
name LIKE ?
OR phone LIKE ?
OR vehicle LIKE ?
");

绑定：

$search = "%".$search."%";

$stmt->bind_param(
"sss",
$search,
$search,
$search
);
修复日期查询
$stmt = $conn->prepare("
SELECT *
FROM cust_details
WHERE date BETWEEN ? AND ?
");
$stmt->bind_param(
"ss",
$startDate,
$endDate
);
修复分页
$start =
max(0,(int)$_POST['start']);

$length =
max(1,min(100,(int)$_POST['length']));
修复排序

建立严格白名单：

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
$orderColumn =
$allowedColumns[$index] ?? 'id';

排序方向：

$orderDir =
strtoupper($dir) === 'ASC'
? 'ASC'
: 'DESC';

绝不直接拼接用户输入。

第二阶段：结构化修复

建议建立统一数据库访问层：

Database.php

统一提供：

select()
insert()
update()
delete()

接口。

禁止业务代码直接：

mysqli_query()
第三阶段：安全加固
WAF规则

拦截：

UNION
SLEEP(
BENCHMARK(
LOAD_FILE(
INTO OUTFILE
数据库权限最小化

业务账号仅授予：

SELECT
INSERT
UPDATE
DELETE

禁止：

FILE
SUPER
GRANT

权限。

错误信息隐藏

生产环境：

display_errors = Off

避免泄露：

syntax error
table name
column name

信息。

SQL审计日志

记录：

用户
IP
查询时间
查询参数

用于追踪攻击行为。

七、安全验证方案

修复后应验证：

测试1
' OR 1=1--

应返回：

无异常
无SQL报错
测试2
UNION SELECT

应被拒绝。

测试3
SLEEP(5)

响应时间不应增加。

测试4

排序参数：

dir=desc,(select sleep(5))

应自动降级为：

DESC
八、最终修复代码（推荐生产版本）
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

$orderIndex =
(int)($_POST['order'][0]['column'] ?? 0);

$orderColumn =
$columns[$orderIndex] ?? 'id';

$orderDir =
(strtoupper($_POST['order'][0]['dir'] ?? '') === 'ASC')
? 'ASC'
: 'DESC';

$start =
max(0,(int)($_POST['start'] ?? 0));

$length =
min(
100,
max(1,(int)($_POST['length'] ?? 25))
);

$search =
'%' . ($_POST['search']['value'] ?? '') . '%';

$sql = "
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
ORDER BY {$orderColumn} {$orderDir}
LIMIT ?, ?
";

$stmt = $conn->prepare($sql);

$stmt->bind_param(
'sssii',
$search,
$search,
$search,
$start,
$length
);

$stmt->execute();
$result = $stmt->get_result();
结论

DrivePulse 的 admin/sortData/fetch.php 存在典型的 CWE-89 SQL Injection 漏洞，其根本原因是多个用户输入被直接拼接进入 SQL 语句，包括搜索、日期过滤、排序和分页参数。攻击者可利用该缺陷实施数据泄露、权限绕过、业务数据篡改甚至数据库接管。最佳修复方案为：全面采用预编译语句 + 排序白名单 + 输入类型校验 + 最小权限数据库账户 + SQL审计机制。该方案不仅修复当前漏洞，也能避免同类问题在项目其他模块重复出现
