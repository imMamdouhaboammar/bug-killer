<?php
// Vulnerable: raw GET input concatenated into SQL query
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '" . $id . "'";
mysqli_query($conn, $query);
?>
