<?php
// SYNTHETIC DEMO FILE - intentionally insecure
$user = $_GET['user'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $_GET['user'] . "'");
echo "Welcome " . $_GET['user'];
$data = unserialize($_COOKIE['session']);
system("ls " . $_GET['dir']);
