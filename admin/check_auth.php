<?php
session_start();
header('Content-Type: application/json');

$isAdmin = isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;

echo json_encode([
    'authenticated' => $isAdmin,
    'user' => $isAdmin ? ($_SESSION['admin_usuario'] ?? 'admin') : null
]);
?>


