<?php
// Safe: PDO prepared statement with bound parameter
$id = $_GET['id'];
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $id]);
$user = $stmt->fetch();
?>
